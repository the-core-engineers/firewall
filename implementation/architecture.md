# Packet Filtering Firewall - Architecture and Implementation

## Overview
This project implements a basic packet filtering firewall consisting of a Python/FastAPI backend and a React/Carbon Design frontend.

## Components

### Backend (Python / FastAPI)
The backend uses FastAPI to provide a REST API for the frontend and `scapy` to perform live network packet sniffing.
- **Packet Sniffing**: Uses `scapy`'s `sniff` function in a background thread to capture network traffic.
- **Rule Engine**: A simple rule engine that evaluates incoming packets against a set of user-defined rules. Rules can allow or block traffic based on protocol, source/destination IP, and ports.
- **API Endpoints**:
  - `GET /rules`, `POST /rules`, `DELETE /rules/{id}`: Manage firewall rules.
  - `POST /test`: Evaluate a simulated packet against current rules without touching the network.
  - `POST /capture/start`, `POST /capture/stop`: Control the live network sniffing thread.
  - `GET /packets`: Retrieve the most recently captured and evaluated packets.

### Frontend (React / Vite)
The frontend is a Single Page Application (SPA) built with React and Vite. It uses the IBM Carbon Design System for a clean, professional UI.
- **Live Network Filter**: Displays a real-time table of packets captured by the backend, showing whether they were allowed or blocked. Includes a toggle to start/stop capture.
- **Firewall Rules**: An interface to view, add, and remove firewall rules. Rules dictate the behavior of the backend packet evaluator.
- **Packet Tester**: A form to simulate a network packet. Users can input protocol, IPs, and ports, and see immediately whether the firewall would allow or block the packet based on current rules.

## Design Decisions
1. **Separation of Concerns**: The network logic and rule evaluation are isolated in the Python backend, while the UI is handled entirely by React.
2. **Real-time Updates**: The frontend polls the backend for new packets every second when capture is active. WebSockets could be an enhancement, but polling keeps the architecture simple and robust for a basic implementation.
3. **Default Policy**: The firewall defaults to an ALLOW policy if no rules match. The first matching rule dictates the action (ALLOW or BLOCK).
4. **Carbon Design**: Used for all UI components to maintain a consistent and accessible design language.
