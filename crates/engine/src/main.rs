//! linuxshield-engine/src/main.rs
//!
//! The Rust engine is the kernel-layer manager for LinuxShield. It:
//!
//!   1. Loads the XDP eBPF program (compiled separately) onto the NIC.
//!   2. Syncs the BLOCKLIST BPF map from the SQLite DB on startup + on-demand.
//!   3. Translates FastAPI firewall rules into nftables and applies them.
//!   4. Starts Suricata in NFQUEUE inline mode and tails eve.json for alerts.
//!   5. Exposes a local HTTP API on 127.0.0.1:7070 so FastAPI can call us.
//!
//! FastAPI is intentionally kept unaware of eBPF / nftables internals.
//! It just calls our REST endpoints, the same way it used to call engine.py.

mod api;       // Axum HTTP handlers (the interface FastAPI talks to)
mod bpf;       // Aya: XDP program loading + BPF map management
mod nftables;  // nftables rule translation + atomic application
mod suricata;  // Suricata process management + eve.json alert tail

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

// ─────────────────────────────────────────────────────────────────────────────
// Shared state passed to every Axum handler via Arc
// ─────────────────────────────────────────────────────────────────────────────
pub struct EngineState {
    pub bpf:       Arc<Mutex<aya::Bpf>>,  // owns the loaded eBPF object
    pub db:        sqlx::SqlitePool,       // read rules / blocklist
    pub alerts:    Arc<RwLock<Vec<serde_json::Value>>>, // buffered Suricata alerts
    pub interface: String,                 // NIC name, e.g. "eth0"
}

#[tokio::main]
async fn main() -> Result<()> {
    // ── 0. Initialise structured logging ────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("linuxshield_engine=debug".parse()?))
        .init();

    let iface = std::env::var("LINUXSHIELD_IFACE").unwrap_or("eth0".to_string());
    let db_path = std::env::var("LINUXSHIELD_DB")
        .unwrap_or("core/firewall.db".to_string());

    info!("LinuxShield engine starting on interface {}", iface);

    // ── 1. Connect to the SQLite DB (written by FastAPI) ────────────────────
    let db = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path)).await?;
    info!("Connected to DB at {}", db_path);

    // ── 2. Load the compiled eBPF object file and attach XDP ────────────────
    //    The bytes are embedded at compile time — no runtime file dependency.
    let mut bpf = bpf::load_and_attach(&iface).await?;
    let bpf_arc = Arc::new(Mutex::new(bpf));

    // ── 3. Sync blocklist from DB → BPF map at startup ──────────────────────
    {
        let mut bpf = bpf_arc.lock().await;
        let count = bpf::sync_blocklist(&mut bpf, &db).await?;
        info!("Synced {} blocklist entries into XDP map", count);
    }

    // ── 4. Apply current rules to nftables ──────────────────────────────────
    nftables::apply_rules_from_db(&db).await?;
    info!("nftables rules applied");

    // ── 5. Start Suricata IPS ────────────────────────────────────────────────
    let alerts = Arc::new(RwLock::new(Vec::new()));
    let alerts_clone = alerts.clone();
    tokio::spawn(async move {
        if let Err(e) = suricata::run(alerts_clone).await {
            warn!("Suricata task exited: {:?}", e);
        }
    });

    // ── 6. Start internal Axum API on 127.0.0.1:7070 ────────────────────────
    let state = Arc::new(EngineState {
        bpf: bpf_arc,
        db,
        alerts,
        interface: iface,
    });

    let router = api::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7070").await?;
    info!("Engine API listening on 127.0.0.1:7070");
    axum::serve(listener, router).await?;

    Ok(())
}
