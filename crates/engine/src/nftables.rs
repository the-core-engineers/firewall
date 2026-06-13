//! crates/engine/src/nftables.rs
//!
//! Translates the rules stored in SQLite by FastAPI into an nftables ruleset
//! and applies it **atomically** using `nft -f <file>`.
//!
//! WHY nftables (and not raw iptables)?
//! ─────────────────────────────────────
//! • Atomic replacement: `nft -f <file>` can flush + re-add all rules in a
//!   single kernel transaction.  No window where the firewall has no rules.
//! • Nesting: tables → chains → rules is more expressive than flat iptables.
//! • Conntrack built-in: `ct state established,related accept` is one line.
//! • Future: nftables can queue packets to Suricata via NFQUEUE natively.
//!
//! HOW SURICATA INTEGRATES
//! ───────────────────────
//! The FORWARD chain has a rule:  `queue num 0 bypass`
//! This sends accepted packets to Suricata via NFQUEUE 0.  Suricata either
//! NF_ACCEPTs them (clean) or NF_DROPs them (signature match).
//! `bypass` means if Suricata isn't running, packets pass through anyway
//! (fail-open).  Change to plain `queue num 0` for fail-closed.

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use std::fmt::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use tracing::{debug, info};

#[derive(Debug, sqlx::FromRow)]
struct RuleRow {
    action:      String,
    protocol:    String,
    #[sqlx(rename = "srcIp")]
    src_ip:      Option<String>,
    #[sqlx(rename = "dstIp")]
    dst_ip:      Option<String>,
    #[sqlx(rename = "srcPort")]
    src_port:    Option<String>,
    #[sqlx(rename = "dstPort")]
    dst_port:    Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SettingRow {
    key:   String,
    value: String,
}

/// Read rules from DB and atomically replace the nftables ruleset.
pub async fn apply_rules_from_db(pool: &SqlitePool) -> Result<()> {
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT action, protocol, srcIp, dstIp, srcPort, dstPort FROM rules"
    )
    .fetch_all(pool)
    .await
    .context("Failed to read rules from DB")?;

    let settings: Vec<SettingRow> = sqlx::query_as("SELECT key, value FROM settings")
        .fetch_all(pool)
        .await
        .context("Failed to read settings from DB")?;

    let settings_map: std::collections::HashMap<&str, &str> = settings
        .iter()
        .map(|s| (s.key.as_str(), s.value.as_str()))
        .collect();

    let default_policy = settings_map.get("default_policy").copied().unwrap_or("accept");
    let nft_default = if default_policy.to_uppercase() == "DROP" { "drop" } else { "accept" };

    let ruleset = build_ruleset(&rules, nft_default);
    debug!("Generated nftables ruleset:\n{}", ruleset);
    apply_ruleset(&ruleset).await
}

/// Build the complete nftables ruleset string.
fn build_ruleset(rules: &[RuleRow], default_policy: &str) -> String {
    let mut s = String::new();

    // Flush everything and start fresh — this is the atomic replace strategy.
    writeln!(s, "flush ruleset").unwrap();
    writeln!(s).unwrap();

    // The main table — we use "inet" family which covers both IPv4 and IPv6.
    writeln!(s, "table inet linuxshield {{").unwrap();

    // ── INPUT chain (traffic destined for this machine) ──────────────────────
    writeln!(s, "  chain input {{").unwrap();
    writeln!(s, "    type filter hook input priority 0; policy {};", default_policy).unwrap();
    writeln!(s).unwrap();
    writeln!(s, "    # Allow loopback").unwrap();
    writeln!(s, "    iif lo accept").unwrap();
    writeln!(s).unwrap();
    writeln!(s, "    # Allow established/related connections (stateful firewall)").unwrap();
    writeln!(s, "    ct state established,related accept").unwrap();
    writeln!(s, "    ct state invalid drop").unwrap();
    writeln!(s).unwrap();
    writeln!(s, "    # Allow ICMP (ping) — essential for network diagnostics").unwrap();
    writeln!(s, "    ip protocol icmp accept").unwrap();
    writeln!(s, "    ip6 nexthdr icmpv6 accept").unwrap();
    writeln!(s).unwrap();

    // Translate user rules
    for rule in rules {
        if let Some(nft_rule) = translate_rule(rule, "input") {
            writeln!(s, "    {}", nft_rule).unwrap();
        }
    }

    writeln!(s, "  }}").unwrap();
    writeln!(s).unwrap();

    // ── FORWARD chain (traffic being routed through this machine as a gateway) ─
    writeln!(s, "  chain forward {{").unwrap();
    writeln!(s, "    type filter hook forward priority 0; policy drop;").unwrap();
    writeln!(s).unwrap();
    writeln!(s, "    ct state established,related accept").unwrap();
    writeln!(s).unwrap();
    writeln!(s, "    # Send accepted packets to Suricata via NFQUEUE 0.").unwrap();
    writeln!(s, "    # 'bypass' = fail-open if Suricata is not running.").unwrap();
    writeln!(s, "    # Remove 'bypass' for fail-closed (more secure but risky).").unwrap();
    writeln!(s, "    queue num 0 bypass").unwrap();
    writeln!(s, "  }}").unwrap();
    writeln!(s).unwrap();

    // ── OUTPUT chain ──────────────────────────────────────────────────────────
    writeln!(s, "  chain output {{").unwrap();
    writeln!(s, "    type filter hook output priority 0; policy accept;").unwrap();
    writeln!(s, "  }}").unwrap();

    writeln!(s, "}}").unwrap();
    s
}

/// Translate a single DB rule row into one nft rule statement.
/// Returns None if the rule can't be translated (e.g. unsupported protocol).
fn translate_rule(rule: &RuleRow, chain: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    // Protocol
    match rule.protocol.to_uppercase().as_str() {
        "TCP"  => parts.push("ip protocol tcp".into()),
        "UDP"  => parts.push("ip protocol udp".into()),
        "ICMP" => parts.push("ip protocol icmp".into()),
        "ALL"  => {} // no protocol constraint
        _      => return None,
    }

    // Source IP (exact match or CIDR)
    if let Some(ref src) = rule.src_ip {
        if !src.is_empty() {
            parts.push(format!("ip saddr {}", src));
        }
    }

    // Destination IP
    if let Some(ref dst) = rule.dst_ip {
        if !dst.is_empty() {
            parts.push(format!("ip daddr {}", dst));
        }
    }

    // Source port (single, range "80-443", or list "80,443,8080")
    if let Some(ref sp) = rule.src_port {
        if !sp.is_empty() {
            let proto = rule.protocol.to_lowercase();
            if proto == "tcp" || proto == "udp" {
                parts.push(format!("{} sport {}", proto, to_nft_port(sp)));
            }
        }
    }

    // Destination port
    if let Some(ref dp) = rule.dst_port {
        if !dp.is_empty() {
            let proto = rule.protocol.to_lowercase();
            if proto == "tcp" || proto == "udp" {
                parts.push(format!("{} dport {}", proto, to_nft_port(dp)));
            }
        }
    }

    // Action
    let action = match rule.action.to_uppercase().as_str() {
        "ALLOW" => "accept",
        "DROP"  => "drop",
        "BLOCK" => "drop",
        _       => return None,
    };
    parts.push(action.to_string());

    Some(parts.join(" "))
}

/// Convert our port syntax to nftables port syntax.
///   "80"        → "80"
///   "80-443"    → "80-443"
///   "80,443"    → "{ 80, 443 }"
fn to_nft_port(port_str: &str) -> String {
    if port_str.contains(',') {
        // nftables anonymous set syntax
        let ports: Vec<&str> = port_str.split(',').map(str::trim).collect();
        format!("{{ {} }}", ports.join(", "))
    } else {
        // single port or range — nftables accepts "80-443" directly
        port_str.to_string()
    }
}

/// Write the ruleset to a temp file and apply atomically via `nft -f`.
async fn apply_ruleset(ruleset: &str) -> Result<()> {
    // Write to a temp file
    let tmp = NamedTempFile::new().context("Failed to create temp file for nft rules")?;
    std::fs::write(tmp.path(), ruleset)
        .context("Failed to write nft ruleset to temp file")?;

    // Apply atomically — if nft returns non-zero, we return an error
    // and the OLD ruleset stays in place.
    let output = Command::new("nft")
        .arg("-f")
        .arg(tmp.path())
        .output()
        .context("Failed to run 'nft' — is nftables installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft returned error: {}", stderr);
    }

    info!("nftables ruleset applied successfully");
    Ok(())
}
