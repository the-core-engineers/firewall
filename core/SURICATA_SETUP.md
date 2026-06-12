# Suricata & pf Configuration Guide (macOS)

This document provides the instructions necessary to deploy the Intrusion Detection System (Suricata) and kernel-level packet filtering (`pf`) on your target macOS environment. 

> **WARNING**: Do not execute these steps on your development machine unless you explicitly intend to start intercepting traffic locally.

## 1. Prerequisites (macOS & Linux)

### macOS (Host Machine)
Ensure you have Homebrew installed on the target machine.
```bash
brew update
brew install suricata
```

### Linux (Ubuntu Server 22.04 / 24.04)
Suricata is maintained in an official PPA by the OISF.
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```

## 2. Suricata Configuration (`suricata.yaml`)

- **macOS:** `/opt/homebrew/etc/suricata/suricata.yaml` (Apple Silicon) or `/usr/local/etc/suricata/suricata.yaml` (Intel).
- **Linux:** `/etc/suricata/suricata.yaml`

You must modify `suricata.yaml` to ensure it outputs its JSON logs directly to the firewall's `core` directory so the Python orchestrator can read them in real-time.

Find the `outputs` section and configure `eve-log`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /absolute/path/to/FirewallRepo/core/eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
        - flow
        - drop
```

## 3. Managing Suricata Rules
Suricata uses the Emerging Threats (ET) ruleset by default. To download and update the rules to the latest signatures, run:

```bash
sudo suricata-update
```
This will place the consolidated rules file in `/opt/homebrew/var/lib/suricata/rules/suricata.rules`. Ensure your `suricata.yaml` points to this file in the `rule-files:` section.

## 4. Running the Engine

The Python orchestrator (`core/engine.py`) has been rewritten to manage macOS `pf` and tail the `eve.json` file. 

To start the packet capture and DPI on the target machine, you will need to start Suricata explicitly targeting the active network interface (e.g., `en0` for Wi-Fi).

```bash
sudo suricata -c /opt/homebrew/etc/suricata/suricata.yaml -i en0
```

Once Suricata is running and writing to `eve.json`, start your FastAPI backend:

```bash
sudo python3 -m uvicorn main:app --reload
```

## 5. OS-Agnostic Kernel Integration (DEPRECATED)
The old Python backend (`core/engine.py`) previously managed macOS `pf` and Linux `iptables`. **This has been completely stripped out.**

The firewall now utilizes a strictly decoupled **Hybrid Architecture**:
- **Python FastAPI** continues to serve the React WebUI and API.
- **Rust Data Plane** (located in `core/rust-engine`) handles all actual packet dropping natively at the hardware level using **eBPF/XDP** and **nftables**.

Because of the reliance on native Linux eBPF, **the firewall engine can no longer run on macOS or Windows**. You must deploy it to a Linux environment.

For complete deployment and compilation instructions for the new XDP engine, refer to the new documentation:
- **[Rust Engine README](../rust-engine/README.md)**
- **[Comprehensive Testing Guide](../../manual/TESTING_GUIDE.md)**
