//! crates/engine/src/api.rs
//!
//! Internal Axum HTTP API on 127.0.0.1:7070
//!
//! FastAPI calls these endpoints instead of doing kernel operations directly.
//! This is the ONLY interface between Python and the kernel layers.
//!
//! Endpoints:
//!   POST  /blocklist/add      { "ip": "1.2.3.4" }
//!   POST  /blocklist/remove   { "ip": "1.2.3.4" }
//!   POST  /blocklist/sync     (full re-sync from DB)
//!   POST  /rules/apply        (re-apply all rules from DB to nftables)
//!   GET   /alerts             (recent Suricata alerts)
//!   DELETE /alerts            (clear alert buffer)
//!   GET   /stats              (BPF drop/pass counters)
//!   GET   /health             (liveness check)

use crate::{bpf, nftables, EngineState};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::warn;

pub fn build_router(state: Arc<EngineState>) -> Router {
    Router::new()
        .route("/health",             get(health))
        .route("/blocklist/add",      post(blocklist_add))
        .route("/blocklist/remove",   post(blocklist_remove))
        .route("/blocklist/sync",     post(blocklist_sync))
        .route("/rules/apply",        post(rules_apply))
        .route("/alerts",             get(get_alerts).delete(clear_alerts))
        .route("/stats",              get(get_stats))
        .layer(CorsLayer::permissive()) // allow FastAPI on same host
        .with_state(state)
}

// ─────────────────────────────────────────────────────────────────────────────
// Request / Response types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IpPayload {
    ip: String,
}

#[derive(Serialize)]
struct OkResponse {
    ok:      bool,
    message: String,
}

impl OkResponse {
    fn ok(msg: impl Into<String>) -> Json<Self> {
        Json(Self { ok: true, message: msg.into() })
    }
    fn err(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(Self { ok: false, message: msg.into() }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "linuxshield-engine" }))
}

/// Add a single IP to the XDP BLOCKLIST map immediately.
/// FastAPI calls this right after writing the IP to its DB.
async fn blocklist_add(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<IpPayload>,
) -> Result<Json<OkResponse>, (StatusCode, Json<OkResponse>)> {
    let mut bpf = state.bpf.lock().await;
    bpf::add_to_blocklist(&mut bpf, &payload.ip)
        .map(|_| OkResponse::ok(format!("{} added to XDP blocklist", payload.ip)))
        .map_err(|e| OkResponse::err(e.to_string()))
}

/// Remove a single IP from the XDP BLOCKLIST map.
async fn blocklist_remove(
    State(state): State<Arc<EngineState>>,
    Json(payload): Json<IpPayload>,
) -> Result<Json<OkResponse>, (StatusCode, Json<OkResponse>)> {
    let mut bpf = state.bpf.lock().await;
    bpf::remove_from_blocklist(&mut bpf, &payload.ip)
        .map(|_| OkResponse::ok(format!("{} removed from XDP blocklist", payload.ip)))
        .map_err(|e| OkResponse::err(e.to_string()))
}

/// Full re-sync: read the entire blocklist table from DB and repopulate the BPF map.
/// Use this to recover from inconsistency or after bulk DB changes.
async fn blocklist_sync(
    State(state): State<Arc<EngineState>>,
) -> Result<Json<OkResponse>, (StatusCode, Json<OkResponse>)> {
    let mut bpf = state.bpf.lock().await;
    bpf::sync_blocklist(&mut bpf, &state.db)
        .await
        .map(|count| OkResponse::ok(format!("Synced {} entries into XDP map", count)))
        .map_err(|e| OkResponse::err(e.to_string()))
}

/// Re-read all rules from DB and atomically replace the nftables ruleset.
/// FastAPI calls this after any rule add/delete/update.
async fn rules_apply(
    State(state): State<Arc<EngineState>>,
) -> Result<Json<OkResponse>, (StatusCode, Json<OkResponse>)> {
    nftables::apply_rules_from_db(&state.db)
        .await
        .map(|_| OkResponse::ok("nftables ruleset updated"))
        .map_err(|e| OkResponse::err(e.to_string()))
}

/// Return the latest Suricata alerts.
/// FastAPI polls this and forwards results to the Web UI.
async fn get_alerts(
    State(state): State<Arc<EngineState>>,
) -> Json<Vec<serde_json::Value>> {
    let buf = state.alerts.read().await;
    // Return in reverse-chronological order (newest first)
    Json(buf.iter().cloned().rev().collect())
}

/// Clear the in-memory alert buffer.
async fn clear_alerts(State(state): State<Arc<EngineState>>) -> Json<OkResponse> {
    state.alerts.write().await.clear();
    OkResponse::ok("Alert buffer cleared")
}

/// Return per-CPU packet stats from the BPF STATS map.
/// Summed across all CPUs before returning.
async fn get_stats(
    State(state): State<Arc<EngineState>>,
) -> Json<serde_json::Value> {
    // Reading per-CPU arrays requires iterating over each CPU's value
    // and summing them.  This is safe to do while the XDP program runs.
    let bpf = state.bpf.lock().await;

    let (dropped_pkts, dropped_bytes, passed_pkts, passed_bytes) =
        read_stats(&bpf).unwrap_or((0, 0, 0, 0));

    Json(serde_json::json!({
        "xdp_dropped_packets": dropped_pkts,
        "xdp_dropped_bytes":   dropped_bytes,
        "xdp_passed_packets":  passed_pkts,
        "xdp_passed_bytes":    passed_bytes,
    }))
}

/// Sum per-CPU STATS map values.  Returns (drop_pkts, drop_bytes, pass_pkts, pass_bytes).
fn read_stats(bpf: &aya::Bpf) -> anyhow::Result<(u64, u64, u64, u64)> {
    use aya::maps::PerCpuArray;

    // The map stores [Stats; 2]: index 0 = drops, index 1 = passes
    // PerCpuValues<Stats> is a Vec with one entry per logical CPU.
    let stats_map: PerCpuArray<_, crate::suricata::Stats> =
        PerCpuArray::try_from(bpf.map("STATS").ok_or(anyhow::anyhow!("STATS map missing"))?)?;

    let drops  = stats_map.get(&0, 0)?;
    let passes = stats_map.get(&1, 0)?;

    let (d_pkts, d_bytes) = drops.iter()
        .fold((0u64, 0u64), |acc, s| (acc.0 + s.count, acc.1 + s.bytes));
    let (p_pkts, p_bytes) = passes.iter()
        .fold((0u64, 0u64), |acc, s| (acc.0 + s.count, acc.1 + s.bytes));

    Ok((d_pkts, d_bytes, p_pkts, p_bytes))
}
