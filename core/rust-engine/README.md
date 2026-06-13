# Rust XDP & eBPF Data Plane

This directory contains the high-performance Rust orchestrator that interfaces natively with the Linux kernel via eBPF (XDP) and handles threat mitigation at the Network Interface Card (NIC) level.

## Architecture
- **Control Plane (Python FastAPI)**: Handles the React WebUI, authentication, and writes rules/blocklists to the SQLite database (`firewall.db`).
- **Data Plane (Rust Daemon)**: Runs completely asynchronously in the background. It polls `firewall.db` and tails Suricata's `eve.json`. 
- **eBPF Kernel (Aya)**: The Rust daemon injects an XDP program into your NIC driver. When the Rust daemon detects an attacker (either via UI blocklist or a high-severity Suricata alert), it instantly writes the attacker's IP to the shared eBPF `BLOCKLIST` Map. The NIC hardware drops the packet before it even touches the Linux kernel stack.

## Compilation & Deployment (Linux Only)

> **Note:** eBPF compilation requires Rust Nightly and the `bpf-linker`. You must perform these steps on your deployment Linux VM, not macOS.

### 1. Install Rust Prerequisites
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

### 2. Compile the eBPF Kernel Program
The kernel code must be specifically compiled for the `ebpfel-unknown-none` target architecture using the unstable `build-std` feature to compile the Rust core library for the kernel.
```bash
cd rust-engine-ebpf
cargo +nightly build --target ebpfel-unknown-none -Z build-std=core --release
```

### 3. Compile the Userspace Daemon
```bash
cd ../rust-engine
cargo build --release
```

### 4. Run the Daemon
Because the orchestrator must manipulate kernel eBPF maps and attach to the NIC, it requires `root` privileges.
```bash
sudo RUST_LOG=info ./target/release/rust-engine
```

The orchestrator will now run in the background, listening for WebUI updates and Suricata alerts, continuously updating the XDP maps at zero-latency!
