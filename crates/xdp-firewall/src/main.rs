//! xdp-firewall/src/main.rs
//!
//! This program runs INSIDE the Linux kernel at the XDP hook — the earliest
//! possible point in the packet receive path, BEFORE the kernel allocates any
//! socket buffers (sk_buff). This is what gives XDP its "zero-copy" speed:
//! for blocked IPs the kernel never even allocates memory for the packet.
//!
//! Compile target: bpfel-unknown-none  (little-endian BPF)
//! Load & attach:  crates/engine (userspace, uses Aya)

#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie, PerCpuArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ─────────────────────────────────────────────────────────────────────────────
// BPF MAPS  (shared memory between eBPF program and userspace Rust engine)
// ─────────────────────────────────────────────────────────────────────────────

/// Blocklist: LPM (Longest Prefix Match) trie keyed by IPv4 address.
///
/// Why LPM trie?  It lets us block entire subnets (CIDR ranges) just as
/// efficiently as single IPs.  A /32 entry blocks one IP, a /24 blocks
/// a whole subnet.  The kernel does the prefix lookup in O(prefix_len).
///
/// Key   = (prefix_len: u32, addr: u32)   — addr in NETWORK byte order
/// Value = u32 (unused, just a marker that the IP is blocked)
#[map]
static BLOCKLIST: LpmTrie<u32, u32> = LpmTrie::with_max_entries(65_536, 0);

/// Per-CPU counters so we never need atomic ops in the hot path.
/// Index 0 = dropped packets,  index 1 = passed packets
#[repr(C)]
pub struct Stats {
    pub count: u64,
    pub bytes: u64,
}

#[map]
static mut STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(2, 0);

// ─────────────────────────────────────────────────────────────────────────────
// XDP ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

/// `xdp` macro registers this function with the BPF verifier as an XDP program.
/// The kernel calls it for EVERY incoming packet on the attached interface.
#[xdp]
pub fn linuxshield_xdp(ctx: XdpContext) -> u32 {
    match try_xdp_filter(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED, // parsing error → let kernel handle it
    }
}

fn try_xdp_filter(ctx: &XdpContext) -> Result<u32, ()> {
    // ── Step 1: Parse Ethernet header ────────────────────────────────────────
    // ptr_at<T>(offset) gives us a *const T that the BPF verifier has proven
    // sits within [data, data_end).  If there aren't enough bytes, it returns
    // Err(()) and the match above returns XDP_ABORTED.
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;

    // ── Step 2: Only handle IPv4 (pass IPv6, ARP, etc. through untouched) ───
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // ── Step 3: Parse IPv4 header ─────────────────────────────────────────
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;

    // src_addr is in network byte order (big-endian).
    // We convert to host byte order for the map lookup.
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // ── Step 4: Blocklist check ───────────────────────────────────────────
    // Key::new(prefix_len, addr) — prefix_len=32 means exact /32 host match.
    // The LPM trie will also match /24, /16, etc. if those are in the map.
    let key = Key::new(32, src_addr.to_be()); // addr back to network order for trie

    if unsafe { BLOCKLIST.get(&key) }.is_some() {
        // Update drop stats (per-CPU, no atomic needed)
        if let Some(stats) = unsafe { STATS.get_ptr_mut(0) } {
            unsafe {
                (*stats).count += 1;
                (*stats).bytes += u64::from(ctx.data_end() - ctx.data());
            }
        }
        // XDP_DROP: the kernel frees the packet descriptor immediately.
        // No sk_buff allocated, no interrupt handler, no protocol stack.
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Step 5: Update pass stats ─────────────────────────────────────────
    if let Some(stats) = unsafe { STATS.get_ptr_mut(1) } {
        unsafe {
            (*stats).count += 1;
            (*stats).bytes += u64::from(ctx.data_end() - ctx.data());
        }
    }

    Ok(xdp_action::XDP_PASS)
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/// Checked pointer arithmetic.  The BPF verifier REQUIRES us to prove every
/// memory access is within [ctx.data(), ctx.data_end()).  This helper does
/// that proof by comparing (start + offset + size_of::<T>) against data_end.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// Required no_std panic handler — the BPF verifier rejects programs that
/// could panic, so this should never actually be called.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
