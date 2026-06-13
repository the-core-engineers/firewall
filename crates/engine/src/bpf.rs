//! crates/engine/src/bpf.rs
//!
//! Loads the compiled XDP eBPF program and manages the BLOCKLIST BPF map.
//!
//! HOW THE EMBED WORKS
//! -------------------
//! include_bytes_aligned! embeds the compiled eBPF ELF (xdp-firewall binary)
//! directly into the engine executable at compile time.  At runtime, Aya
//! parses that ELF, relocates it, and loads it into the kernel via the
//! bpf(2) syscall.  No separate .o file needs to be deployed.
//!
//! BUILD ORDER
//! -----------
//! 1.  cargo build -p xdp-firewall --target bpfel-unknown-none --release -Z build-std=core
//! 2.  cargo build -p linuxshield-engine --release

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::lpm_trie::{Key, LpmTrie},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use ipnetwork::IpNetwork;
use sqlx::SqlitePool;
use std::net::Ipv4Addr;
use tracing::info;

/// Load the embedded eBPF ELF, attach it to `iface` in SKB mode.
///
/// XdpFlags::SKB_MODE  — works with any driver (softirq path).
///   For maximum performance on a server NIC that supports native XDP,
///   switch to XdpFlags::DRV_MODE. The blocklist logic is identical;
///   DRV mode just eliminates one extra copy per packet.
pub async fn load_and_attach(iface: &str) -> Result<Bpf> {
    // The eBPF bytecode is embedded at compile time.
    // Path is relative to the *workspace root*.
    let bpf_bytes = include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-firewall"
    );

    let mut bpf = Bpf::load(bpf_bytes)
        .context("Failed to load eBPF object — did you compile xdp-firewall first?")?;

    // Enable aya's kernel log forwarding so tracing::info! inside the
    // eBPF program shows up in our structured log output.
    if let Err(e) = aya_log::BpfLogger::init(&mut bpf) {
        tracing::warn!("eBPF logger init failed (non-fatal): {}", e);
    }

    // Fetch the XDP program by name (must match the #[xdp] fn name).
    let program: &mut Xdp = bpf
        .program_mut("linuxshield_xdp")
        .context("XDP program 'linuxshield_xdp' not found in eBPF object")?
        .try_into()?;

    program.load().context("BPF verifier rejected the program")?;
    program
        .attach(iface, XdpFlags::SKB_MODE)
        .with_context(|| format!("Failed to attach XDP to interface {}", iface))?;

    info!("XDP program attached to {} in SKB mode", iface);
    Ok(bpf)
}

/// Sync the BLOCKLIST BPF LPM trie from the SQLite blocklist table.
///
/// Called at startup and whenever FastAPI tells us the blocklist changed
/// (POST /engine/blocklist/sync).
///
/// The BPF trie supports CIDR prefixes (e.g. "192.168.1.0/24") as well as
/// single IPs (/32).  We store each entry as:
///   key   = Key::new(prefix_len, addr_in_network_byte_order)
///   value = 1u32  (the value is irrelevant — only presence matters)
pub async fn sync_blocklist(bpf: &mut Bpf, pool: &SqlitePool) -> Result<usize> {
    // Fetch all IPs from the blocklist table.
    let rows: Vec<(String,)> = sqlx::query_as("SELECT ip FROM blocklist")
        .fetch_all(pool)
        .await
        .context("DB read failed for blocklist")?;

    // Get a mutable reference to the BLOCKLIST map.
    let mut trie: LpmTrie<_, u32, u32> = LpmTrie::try_from(
        bpf.map_mut("BLOCKLIST")
            .context("BLOCKLIST map not found in eBPF object")?,
    )?;

    let mut count = 0usize;

    for (ip_str,) in &rows {
        // Parse as CIDR (e.g. "1.2.3.4" → /32, "10.0.0.0/8" → /8)
        let network: IpNetwork = match ip_str.parse() {
            Ok(n) => n,
            Err(_) => {
                // Try parsing as bare IP and append /32
                match format!("{}/32", ip_str).parse() {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("Skipping unparseable blocklist entry '{}': {}", ip_str, e);
                        continue;
                    }
                }
            }
        };

        // Only IPv4 is handled by the XDP program.
        // IPv6 blocklist can be a future nftables responsibility.
        let IpNetwork::V4(v4) = network else { continue };

        let addr_u32: u32 = u32::from(v4.network()); // network address in host order
        let key = Key::new(v4.prefix() as u32, addr_u32.to_be()); // back to network order

        // flags = 0 means BPF_ANY (insert or update)
        trie.insert(&key, 1u32, 0)
            .with_context(|| format!("Failed to insert {} into BPF map", ip_str))?;
        count += 1;
    }

    info!("Blocklist sync complete: {} entries in XDP map", count);
    Ok(count)
}

/// Add a single IP (or CIDR) to the BLOCKLIST BPF map without a full re-sync.
/// FastAPI calls POST /engine/blocklist/add after writing to the DB.
pub fn add_to_blocklist(bpf: &mut Bpf, ip_str: &str) -> Result<()> {
    let network: IpNetwork = if ip_str.contains('/') {
        ip_str.parse()?
    } else {
        format!("{}/32", ip_str).parse()?
    };

    let IpNetwork::V4(v4) = network else {
        return Ok(()); // IPv6 not handled at XDP layer
    };

    let mut trie: LpmTrie<_, u32, u32> = LpmTrie::try_from(
        bpf.map_mut("BLOCKLIST")
            .context("BLOCKLIST map not found")?,
    )?;

    let addr_u32: u32 = u32::from(v4.network());
    let key = Key::new(v4.prefix() as u32, addr_u32.to_be());
    trie.insert(&key, 1u32, 0)?;

    info!("Added {} to XDP BLOCKLIST", ip_str);
    Ok(())
}

/// Remove a single IP from the BLOCKLIST BPF map.
/// FastAPI calls POST /engine/blocklist/remove after deleting from DB.
pub fn remove_from_blocklist(bpf: &mut Bpf, ip_str: &str) -> Result<()> {
    let network: IpNetwork = if ip_str.contains('/') {
        ip_str.parse()?
    } else {
        format!("{}/32", ip_str).parse()?
    };

    let IpNetwork::V4(v4) = network else { return Ok(()) };

    let mut trie: LpmTrie<_, u32, u32> = LpmTrie::try_from(
        bpf.map_mut("BLOCKLIST")
            .context("BLOCKLIST map not found")?,
    )?;

    let addr_u32: u32 = u32::from(v4.network());
    let key = Key::new(v4.prefix() as u32, addr_u32.to_be());
    trie.remove(&key)?;

    info!("Removed {} from XDP BLOCKLIST", ip_str);
    Ok(())
}
