use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use linemux::MuxedLines;
use log::{info, warn, error};
use rusqlite::Connection;
use std::{net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration, fs, process::Command};
use tokio::{sync::Mutex, time, net::UdpSocket};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    
    // In production, the eBPF code must be compiled for bpfel-unknown-none target first.
    let bpf_path = "../rust-engine-ebpf/target/bpfel-unknown-none/release/rust-engine-ebpf";
    let bpf_data = match std::fs::read(bpf_path) {
        Ok(data) => data,
        Err(_) => {
            warn!("eBPF binary not found. Please compile rust-engine-ebpf first for 'bpfel-unknown-none'.");
            warn!("Running userspace daemon without active XDP enforcement...");
            vec![]
        }
    };

    let bpf_instance = if !bpf_data.is_empty() {
        let mut b = Ebpf::load(&bpf_data)?;
        if let Err(e) = EbpfLogger::init(&mut b) {
            warn!("failed to initialize eBPF logger: {}", e);
        }
        
        // Load the eBPF program into the kernel
        let program: &mut Xdp = b.program_mut("rust_engine").unwrap().try_into()?;
        program.load()?;
        
        // Determine the network interface. Defaulting to enp2s0 for Fedora VMs, but allow IFACE env var override.
        let iface = std::env::var("IFACE").unwrap_or_else(|_| "enp2s0".to_string());
        program.attach(&iface, XdpFlags::default())
            .context(format!("failed to attach the XDP program to interface {}", iface))?;
        
        Some(b)
    } else {
        None
    };

    info!("Rust Data Plane orchestrator started. Watching DB and Suricata...");
    
    // The shared thread-safe BPF wrapper
    let bpf_wrapper = Arc::new(Mutex::new(bpf_instance));

    // Perform an initial sync on startup
    if let Err(e) = sync_sqlite_to_ebpf(&bpf_wrapper).await {
        error!("Initial XDP SQLite sync error: {}", e);
    }
    if let Err(e) = sync_nftables().await {
        error!("Initial NFTables sync error: {}", e);
    }

    // Task 1: UDP IPC Listener (replaces the 5-second polling loop)
    let bpf_clone = bpf_wrapper.clone();
    tokio::spawn(async move {
        let socket = UdpSocket::bind("127.0.0.1:9999").await.expect("Failed to bind UDP IPC port");
        let mut buf = [0; 1024];
        info!("Listening for IPC SYNC signals on UDP 127.0.0.1:9999...");
        
        loop {
            if let Ok((len, _addr)) = socket.recv_from(&mut buf).await {
                if &buf[..len] == b"SYNC" {
                    info!("Received IPC SYNC signal from Python! Executing instant hardware sync.");
                    if let Err(e) = sync_sqlite_to_ebpf(&bpf_clone).await {
                        error!("XDP SQLite sync error: {}", e);
                    }
                    if let Err(e) = sync_nftables().await {
                        error!("NFTables sync error: {}", e);
                    }
                }
            }
        }
    });

    // Task 2: Suricata eve.json tailing
    let bpf_clone_2 = bpf_wrapper.clone();
    tokio::spawn(async move {
        if let Err(e) = tail_suricata(bpf_clone_2).await {
            error!("Suricata tailing error: {}", e);
        }
    });

    info!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}

async fn sync_sqlite_to_ebpf(bpf_wrapper: &Arc<Mutex<Option<Ebpf>>>) -> Result<(), anyhow::Error> {
    let ips: Vec<String> = {
        let conn = Connection::open("../../firewall.db")?;
        let mut stmt = conn.prepare("SELECT ip FROM blocklist")?;
        let result: Vec<String> = stmt.query_map([], |row| row.get(0))?.filter_map(Result::ok).collect();
        result
    };

    let mut bpf_guard = bpf_wrapper.lock().await;
    if let Some(bpf) = bpf_guard.as_mut() {
        let mut blocklist_map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
        
        for ip_str in ips {
            if let Ok(ip_addr) = Ipv4Addr::from_str(&ip_str) {
                // Convert IP to native u32 format to exactly match u32::from_be() in the eBPF program
                let ip_u32 = u32::from(ip_addr);
                // Insert into XDP map
                let _ = blocklist_map.insert(ip_u32, 1, 0);
            }
        }
    }
    Ok(())
}

async fn sync_nftables() -> Result<(), anyhow::Error> {
    let conn = Connection::open("../../firewall.db")?;
    
    // Select complex rules from the database
    let mut stmt = conn.prepare("SELECT action, protocol, srcIp, dstIp, srcPort, dstPort FROM rules")?;
    
    let rule_iter = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, // action
            row.get::<_, String>(1)?, // protocol
            row.get::<_, Option<String>>(2)?, // srcIp
            row.get::<_, Option<String>>(3)?, // dstIp
            row.get::<_, Option<String>>(4)?, // srcPort
            row.get::<_, Option<String>>(5)?, // dstPort
        ))
    })?;

    // We build an nftables configuration file for the 'inet' family.
    // Ensure the table exists before trying to flush it
    let mut nft_config = String::from("add table inet firewall\n");
    nft_config.push_str("flush table inet firewall\n");
    nft_config.push_str("table inet firewall {\n");
    nft_config.push_str("    chain custom_rules {\n");
    nft_config.push_str("        type filter hook input priority 0; policy accept;\n");

    for rule_res in rule_iter {
        if let Ok((action, protocol, src_ip_opt, dst_ip_opt, src_port_opt, dst_port_opt)) = rule_res {
            let src_ip = src_ip_opt.unwrap_or_default();
            let dst_ip = dst_ip_opt.unwrap_or_default();
            let src_port = src_port_opt.unwrap_or_default();
            let dst_port = dst_port_opt.unwrap_or_default();
            
            let mut rule_line = String::from("        ");

            // Add IP matches
            if !src_ip.is_empty() {
                rule_line.push_str(&format!("ip saddr {} ", src_ip));
            }
            if !dst_ip.is_empty() {
                rule_line.push_str(&format!("ip daddr {} ", dst_ip));
            }

            // Protocol and Port logic
            let mut has_port = false;
            if protocol == "TCP" || protocol == "UDP" {
                let proto_prefix = if protocol == "TCP" { "tcp" } else { "udp" };
                if !src_port.is_empty() {
                    rule_line.push_str(&format!("{} sport {} ", proto_prefix, src_port));
                    has_port = true;
                }
                if !dst_port.is_empty() {
                    rule_line.push_str(&format!("{} dport {} ", proto_prefix, dst_port));
                    has_port = true;
                }
                if !has_port {
                    // No ports specified, just match the protocol entirely
                    rule_line.push_str(&format!("meta l4proto {} ", proto_prefix));
                }
            } else if protocol == "ICMP" {
                rule_line.push_str("meta l4proto icmp ");
            } else if protocol == "ANY" || protocol == "ALL" {
                // If they specify ports but ANY protocol, use 'th' (transport header)
                if !src_port.is_empty() {
                    rule_line.push_str(&format!("th sport {} ", src_port));
                }
                if !dst_port.is_empty() {
                    rule_line.push_str(&format!("th dport {} ", dst_port));
                }
            }

            let action_str = if action == "DROP" {
                "drop"
            } else if action == "REJECT" || action == "DENY" {
                "reject"
            } else {
                "accept"
            };

            rule_line.push_str(action_str);
            rule_line.push_str("\n");
            nft_config.push_str(&rule_line);
        }
    }

    nft_config.push_str("    }\n}\n");

    // Write to a temporary file
    let tmp_path = "/tmp/firewall_custom.nft";
    fs::write(tmp_path, nft_config)?;

    // Execute the nftables load command
    let output = Command::new("sudo")
        .arg("nft")
        .arg("-f")
        .arg(tmp_path)
        .output()?;

    if !output.status.success() {
        error!("nftables update failed: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        info!("Successfully synced NFTables.");
    }

    Ok(())
}

async fn tail_suricata(bpf_wrapper: Arc<Mutex<Option<Ebpf>>>) -> Result<(), anyhow::Error> {
    let eve_path = "../../eve.json";
    
    while !std::path::Path::new(eve_path).exists() {
        time::sleep(Duration::from_secs(1)).await;
    }

    let mut lines = MuxedLines::new()?;
    lines.add_file(eve_path).await?;

    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line.line()) {
            if event["event_type"] == "alert" {
                let severity = event["alert"]["severity"].as_u64().unwrap_or(3);
                let src_ip = event["src_ip"].as_str().unwrap_or("");
                
                // If it's a high severity threat, block it instantly in eBPF
                if severity <= 2 && !src_ip.is_empty() {
                    if let Ok(ip_addr) = Ipv4Addr::from_str(src_ip) {
                        let ip_u32 = u32::from(ip_addr);
                        
                        let mut bpf_guard = bpf_wrapper.lock().await;
                        if let Some(bpf) = bpf_guard.as_mut() {
                            let mut blocklist_map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
                            let _ = blocklist_map.insert(ip_u32, 1, 0);
                            info!("Suricata Alert! Fast-path hardware drop for IP: {}", src_ip);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
