# VM Testing Guide: Windows Firewall in VM, macOS Host

This manual explains how to run the Firewall Core and Web UI inside a Windows Virtual Machine (VM) and how to test its functionality by sending traffic from your macOS Host machine.

## Prerequisites
1. A Windows VM (e.g., using Parallels, VMware Fusion, or VirtualBox) running on your macOS host.
2. Python 3.9+ installed on the Windows VM.
3. Node.js installed on the Windows VM.
4. `Npcap` installed on the Windows VM (required for Python `scapy` packet sniffing on Windows).

## Step 1: Set Up the Windows VM Network
To ensure your macOS Host can communicate with your Windows VM:
1. Open your VM network settings.
2. Ensure the network adapter is set to **Bridged Network** or **Host-Only Adapter**. (Bridged is easiest; the VM gets an IP on your local network).
3. Find the VM's IP address: Open Command Prompt in Windows and run `ipconfig`. Look for the IPv4 Address (e.g., `192.168.1.100`).

## Step 2: Run the Firewall Project in the VM
Copy the `FirewallRepo` project to the Windows VM.

### Start the Core Engine (Backend)
1. Open a Command Prompt or PowerShell in the `/core` directory.
2. Install requirements: `pip install -r requirements.txt` (Make sure `scapy`, `fastapi`, `uvicorn`, `aiosqlite` are installed).
3. Start the server: `python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000`
   *(Using `--host 0.0.0.0` ensures the macOS host can access the API).*

### Start the Web UI
1. Open another Command Prompt in the `/webui` directory.
2. Install dependencies: `npm install`
3. Edit `webui/src/App.jsx` to point to the VM's API if needed. (By default it points to `localhost:8000`, which works if you view the Web UI inside the VM. If viewing from the macOS host, change `localhost` to the VM's IP).
4. Run: `npm run dev -- --host 0.0.0.0`

## Step 3: Configure the Firewall
1. Open the Web UI. (Inside the VM: `http://localhost:5173`. On the Mac Host: `http://<VM_IP>:5173`).
2. Go to the **Settings** tab. Set the *Flood Threshold* to `50` (50 packets per second).
3. Go to the **Live Network Filter** tab and click **Start Capture**.

## Step 4: Test from macOS Host
Open the Terminal application on your macOS host. You will run tests targeting the Windows VM's IP (`<VM_IP>`).

### Test 1: Basic ICMP Ping (Rule Filter Test)
1. In the Web UI, add a Rule: Action `BLOCK`, Protocol `ICMP`.
2. On macOS Terminal:
   ```bash
   ping <VM_IP>
   ```
3. Look at the Web UI's **Live Network Filter**. You should see ICMP packets marked as `BLOCK`.

### Test 2: Rate Limiting
1. Go to Web UI **Settings**. Set *Rate Limit* to `5` (5 packets per minute).
2. On macOS Terminal, ping the VM again or send repeated CURL requests:
   ```bash
   curl http://<VM_IP>:8000/status
   ```
3. Run the curl command 10 times quickly.
4. Check the Web UI. You will see the first 5 packets marked as ALLOW/OTHER, and the 6th packet onward marked as `DROP` with the reason "Rate limit exceeded".
5. Wait one minute, and traffic will flow again.

### Test 3: Flood Detector (Auto-Blocklist)
1. Set the *Rate Limit* back to a high number (e.g., `1000`) and the *Flood Threshold* to a low number (e.g., `20`).
2. We will simulate a flood by using `hping3` or just standard `ping` with a flood interval from macOS.
   ```bash
   sudo ping -f <VM_IP>
   ```
   *(The `-f` flag sends packets as fast as possible).*
3. Let it run for 2-3 seconds, then press `Ctrl+C`.
4. Go to the Web UI **Blocklist** tab. You should now see your macOS Host's IP address automatically added to the blocklist with the reason "Auto-blocked: Exceeded flood threshold".
5. Try any further communication (e.g., `curl http://<VM_IP>:8000/status` or normal `ping`). The Web UI Live Filter will show these packets being `BLOCK`ed instantly by the Blocklist.

## Resetting
To reset your access, go to the **Blocklist** tab in the Web UI and click **Remove** next to your macOS Host's IP.
