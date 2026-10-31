# Two-Device Network Testing Agents
### Sender (Device 1) & Receiver (Device 2)

This directory contains the distributed, cross-platform Network Testing Agents designed to work in tandem with the central Flask Electrical Interference Investigation Tool.

---

## Architecture Overview

```text
agents/
    sender/
        sender_agent.py          # Device 1 Sender Agent service
        sender_config.json       # Sender config (server URL, token, device ID)
    receiver/
        receiver_agent.py        # Device 2 Receiver Agent service
        receiver_config.json     # Receiver config & iperf3/socket server
    common/
        security.py              # Auth tokens, SSL context, strict input sanitization
        system_info.py           # OS, CPU, RAM, and hardware NIC statistics
        interface_monitor.py     # Interface counters, resets, drops, and CRC/FCS deltas
        ping_monitor.py          # Ping, RTT min/max/avg, RFC 3550 jitter, MTU testing
        traceroute.py            # Hop-by-hop latency and route analysis
        dns_test.py              # DNS resolution latency and failure detection
        iperf_manager.py         # iperf3 client/server + native pure-Python socket fallback
        packet_capture.py        # Retransmission and packet stream inspection
        network_tests.py         # Coordinated test suite orchestrator
        agent_communication.py   # Token-authenticated HTTP/HTTPS client with auto-reconnect
    install_windows.bat          # Windows batch installer
    install_windows.ps1          # Windows PowerShell installer
    install_linux.sh             # Linux installer (Ubuntu, Kali Linux, Debian, RHEL)
    requirements.txt             # Lightweight agent dependencies
```

---

## Supported Operating Systems

- **Windows 10 / Windows 11**
- **Ubuntu Linux (20.04, 22.04, 24.04 LTS)**
- **Kali Linux (2023.x, 2024.x)**
- **Debian, Fedora, CentOS, Arch Linux**

---

## Quick Installation

### Windows 10/11
Open PowerShell as Administrator:
```powershell
cd agents
.\install_windows.ps1
```
Or run `install_windows.bat`.

### Ubuntu / Kali Linux
```bash
cd agents
chmod +x install_linux.sh
./install_linux.sh
```

---

## Running the Agents

### Device 1 – Sender
```bash
# On Device 1 (Sender):
python sender/sender_agent.py --server http://192.168.1.100:5000 --id sender-node-01 --token <TOKEN>
```

### Device 2 – Receiver
```bash
# On Device 2 (Receiver):
python receiver/receiver_agent.py --server http://192.168.1.100:5000 --id receiver-node-02 --token <TOKEN>
```

---

## Hardware Counters & CRC/FCS Notice

Standard OS drivers discard malformed Ethernet frames with FCS/CRC errors at the PHY hardware layer. On Linux, `ethtool -S <interface>` is queried if supported by the NIC. On Windows, `Get-NetAdapterStatistics` is queried. If the hardware or driver does not expose physical CRC counters, the agent explicitly reports **"Unsupported by OS/driver"** rather than showing fabricated zeroes.
