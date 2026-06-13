use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
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
    
    // In production, the eBPF code must be compiled for ebpfel-unknown-none target first.
    let bpf_path = "../rust-engine-ebpf/target/ebpfel-unknown-none/release/rust-engine-ebpf";
    let bpf_data = match std::fs::read(bpf_path) {
        Ok(data) => data,
        Err(_) => {
            warn!("eBPF binary not found. Please compile rust-engine-ebpf first for 'ebpfel-unknown-none'.");
            warn!("Running userspace daemon without active XDP enforcement...");
            vec![]
        }
    };

    let bpf_instance = if !bpf_data.is_empty() {
        let mut b = Bpf::load(&bpf_data)?;
        if let Err(e) = EbpfLogger::init(&mut b) {
            warn!("failed to initialize eBPF logger: {}", e);
        }
        
        // Load the eBPF program into the kernel
        let program: &mut Xdp = b.program_mut("rust_engine").unwrap().try_into()?;
        program.load()?;
        
        // Determine the network interface. Defaulting to eth0 for Linux, but should be configurable.
        let iface = "eth0"; 
        program.attach(iface, XdpFlags::default())
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

async fn sync_sqlite_to_ebpf(bpf_wrapper: &Arc<Mutex<Option<Bpf>>>) -> Result<(), anyhow::Error> {
    // Navigate back to where firewall.db is located
    let conn = Connection::open("../../firewall.db")?;
    let mut stmt = conn.prepare("SELECT ip FROM blocklist")?;
    let ips: Vec<String> = stmt.query_map([], |row| row.get(0))?.filter_map(Result::ok).collect();

    let mut bpf_guard = bpf_wrapper.lock().await;
    if let Some(bpf) = bpf_guard.as_mut() {
        let mut blocklist_map: HashMap<_, u32, u8> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
        
        for ip_str in ips {
            if let Ok(ip_addr) = Ipv4Addr::from_str(&ip_str) {
                // XDP processes IPs in big-endian over the wire, but Ipv4Addr octets can be manipulated
                let ip_u32 = u32::from_ne_bytes(ip_addr.octets());
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
            row.get::<_, String>(2)?, // srcIp
            row.get::<_, String>(3)?, // dstIp
            row.get::<_, String>(4)?, // srcPort
            row.get::<_, String>(5)?, // dstPort
        ))
    })?;

    // We build an nftables configuration file for the 'inet' family.
    // This table 'firewall' and chain 'custom_rules' will be completely flushed and rewritten.
    let mut nft_config = String::from("flush table inet firewall\n");
    nft_config.push_str("table inet firewall {\n");
    nft_config.push_str("    chain custom_rules {\n");
    nft_config.push_str("        type filter hook input priority 0; policy accept;\n");

    for rule_res in rule_iter {
        if let Ok((action, protocol, src_ip, dst_ip, src_port, dst_port)) = rule_res {
            let mut rule_line = String::from("        ");

            let proto_str = if protocol == "TCP" {
                "tcp"
            } else if protocol == "UDP" {
                "udp"
            } else {
                "ip protocol"
            };

            // Add IP matches
            if !src_ip.is_empty() {
                rule_line.push_str(&format!("ip saddr {} ", src_ip));
            }
            if !dst_ip.is_empty() {
                rule_line.push_str(&format!("ip daddr {} ", dst_ip));
            }

            // Add Port matches (only valid if TCP or UDP)
            if protocol == "TCP" || protocol == "UDP" {
                if !src_port.is_empty() {
                    rule_line.push_str(&format!("{} sport {} ", proto_str, src_port));
                }
                if !dst_port.is_empty() {
                    rule_line.push_str(&format!("{} dport {} ", proto_str, dst_port));
                }
            } else if protocol != "ALL" {
                // E.g. ICMP
                if protocol == "ICMP" {
                    rule_line.push_str("icmp ");
                }
            }

            let action_str = if action == "DROP" {
                "drop"
            } else if action == "REJECT" {
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

async fn tail_suricata(bpf_wrapper: Arc<Mutex<Option<Bpf>>>) -> Result<(), anyhow::Error> {
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
                        let ip_u32 = u32::from_ne_bytes(ip_addr.octets());
                        
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
