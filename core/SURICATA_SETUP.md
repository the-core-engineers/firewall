# Suricata Configuration Guide (Linux Only)

This document provides the instructions necessary to deploy the Intrusion Detection System (Suricata) on your target Linux environment (e.g., Ubuntu Server).

Because our high-performance Data Plane is written in Rust and utilizes native Linux eBPF (XDP) and `nftables`, **this firewall cannot be run on macOS or Windows.**

## 1. Prerequisites (Fedora Linux)

Suricata is available directly in the default Fedora repositories.
```bash
sudo dnf install suricata jq
```

## 2. Suricata Configuration (`suricata.yaml`)

The primary configuration file is located at `/etc/suricata/suricata.yaml`.

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
This will place the consolidated rules file in `/var/lib/suricata/rules/suricata.rules`. Ensure your `suricata.yaml` points to this file in the `rule-files:` section.

## 4. Running the Engine

The Python orchestrator (`core/engine.py`) serves the REST API and the React WebUI. 

To start the packet capture and DPI on the target machine, you will need to start Suricata explicitly targeting the active network interface (e.g., `eth0`).

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
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
