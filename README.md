# Electrical Interference Investigation Tool for Computer Networks
### Physical-Layer Network Diagnostics, Electromagnetic Telemetry & Root-Cause Forensic Suite

> **Application Title:** Electrical Interference Investigation Tool for Computer Networks  
> **Target Audience:** Senior Network Engineers, Cybersecurity Researchers, Industrial Automation Specialists, and IT Forensic Analysts.  
> **Supported Platforms:** Windows 10/11 / Windows Server, Linux (Ubuntu, Debian, RHEL, Fedora, CentOS, Arch).

---

## Table of Contents
1. [Project Overview & Scientific Methodology](#1-project-overview--scientific-methodology)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Prerequisites & System Requirements](#3-prerequisites--system-requirements)
4. [Step-by-Step Installation Guide](#4-step-by-step-installation-guide)
   - [Windows (PowerShell)](#windows-installation)
   - [Linux / macOS (Bash)](#linux--macos-installation)
5. [Step-by-Step Execution Guide](#5-step-by-step-execution-guide)
6. [Complete Step-by-Step Investigation Walkthrough](#6-complete-step-by-step-investigation-walkthrough)
   - [Phase 1: Baseline Health Assessment (Test A)](#phase-1-baseline-health-assessment-test-a)
   - [Phase 2: Multi-Target Hop Isolation](#phase-2-multi-target-hop-isolation)
   - [Phase 3: Controlled Active Equipment Observation (Test B)](#phase-3-controlled-active-equipment-observation-test-b)
   - [Phase 4: Physical Cable Separation & Rerouting (Test C)](#phase-4-physical-cable-separation--rerouting-test-c)
   - [Phase 5: Shielded Cable Benchmark (Test D)](#phase-5-shielded-cable-benchmark-test-d)
   - [Phase 6: Running the Scientific Correlation Engine](#phase-6-running-the-scientific-correlation-engine)
   - [Phase 7: Wireshark & TShark Packet Dissection](#phase-7-wireshark--tshark-packet-dissection)
   - [Phase 8: Managed Switch SNMP Hardware Counters](#phase-8-managed-switch-snmp-hardware-counters)
   - [Phase 9: Exporting CSV & Generating Technical PDF Reports](#phase-9-exporting-csv--generating-technical-pdf-reports)
7. [Running Benchmark Demonstration Data](#7-running-benchmark-demonstration-data)
8. [Running Automated Unit & Security Tests](#8-running-automated-unit--security-tests)
9. [Detailed Troubleshooting & Hardware Realities](#9-detailed-troubleshooting--hardware-realities)
10. [Application Security, Reliability & Compliance](#10-application-security-reliability--compliance)

---

## 1. Project Overview & Scientific Methodology

Network degradation in industrial, commercial, and enterprise settings is frequently misdiagnosed. IT staff often guess that "electrical noise" or "EMI" is causing packet drops, while overlooking upstream router queue saturation (bufferbloat), duplex mismatches, optical dispersion, or DNS timeouts. Conversely, genuine physical electromagnetic interference (e.g., from Variable Frequency Drives (VFDs), heavy induction motors, elevator hoists, or arc welders) is often ignored because consumer-grade operating systems fail to log corrupt frames.

This application provides an objective, scientific diagnostic platform that:
1. **Collects real hardware telemetry**: Uses low-overhead ICMP subprocesses, OS network adapter performance counters, Wireshark/TShark packet captures, and optional managed switch SNMP polling.
2. **Applies controlled comparative testing (Tests A through D)**: Validates performance under normal conditions, active equipment load, cable rerouting, and shielded cable replacement.
3. **Isolates network segments**: Uses multi-target ping sweeps to differentiate local drop cable faults from upstream WAN/ISP issues.
4. **Never jumps to conclusions**: Distinguishes between Physical-Layer/EMI, Queueing Congestion (Bufferbloat), Routing/WAN issues, and DNS/Application failures.
5. **Enforces electrical safety**: Adheres to strict non-invasive measurement protocols—never instructing users to touch high-voltage apparatus or open electrical cabinets.

---

## 2. End-to-End System Architecture

```
+-----------------------------------------------------------------------------------------+
|                                    PRESENTATION LAYER                                   |
|   HTML5  |  Bootstrap 5.3  |  Chart.js 4 (Dual-Axis RTT & Loss)  |  Interactive SVG     |
+-----------------------------------------------------------------------------------------+
                                         ▲    │
                     JSON Polling / SSE  │    │ User Controls (Start/Stop/Correlate)
                                         │    ▼
+-----------------------------------------------------------------------------------------+
|                                  FLASK REST APPLICATION                                 |
|                                        (app.py)                                         |
+-----------------------------------------------------------------------------------------+
       │                             │                              │
       ▼                             ▼                              ▼
+---------------------+    +---------------------+       +----------------------+
|  MONITORING ENGINE  |    |  INTERFACE COUNTERS |       |   WIRESHARK/TSHARK   |
|  (ping_monitor.py)  |    | (interface_stats.py)|       | (packet_capture.py)  |
|                     |    |                     |       |                      |
| - Subprocess ping   |    | - psutil / netstat  |       | - Live pcapng stream |
| - Non-shell lists   |    | - PowerShell stats  |       | - TCP Retransmission |
| - 11-hour preset    |    | - Linux ethtool -S  |       | - Duplicate ACKs     |
| - Multi-target hop  |    | - Hardware FCS delta|       | - DNS failures / RST |
+---------------------+    +---------------------+       +----------------------+
       │                             │                              │
       └─────────────────────────────┼──────────────────────────────┘
                                     ▼
+-----------------------------------------------------------------------------------------+
|                            SCIENTIFIC CORRELATION ENGINE                                |
|                              (analysis/correlation.py)                                  |
|                                                                                         |
|  * Compares Test A (Baseline) vs Test B (Active) vs Test C (Reroute) vs Test D (Shield) |
|  * Validates Hop Isolation (Hop 1 Gateway vs Hop 3 Remote WAN)                          |
|  * Scores Evidence Quality & Diagnostic Confidence (0 - 100%)                            |
|  * Classifies: EMI/Physical vs Bufferbloat vs Upstream WAN vs DNS vs Inconclusive       |
+-----------------------------------------------------------------------------------------+
            │                                                      │
            ▼                                                      ▼
+-----------------------+                              +-----------------------+
|   SQLITE REPOSITORY   |                              |    REPORTS ENGINE     |
|   (database/db.py)    |                              | (report_generator.py) |
|                       |                              |                       |
| - Parameterized SQL   |                              | - Technical PDF (FPDF)|
| - Benchmark seeding   |                              | - Timestamped CSV     |
+-----------------------+                              +-----------------------+
```

---

## 3. Prerequisites & System Requirements

| Component | Minimum Requirement | Recommended |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11 / Server 2016+ or Linux (Kernel 4.15+) | Windows 11 64-bit or Ubuntu 22.04 LTS |
| **Python** | Python 3.10+ | Python 3.11, 3.12, 3.13, or 3.14 |
| **Memory (RAM)** | 512 MB available | 2 GB+ |
| **Disk Space** | 200 MB free space | 1 GB+ (for long-duration PCAP files) |
| **Browser** | Modern Web Browser | Chrome, Edge, Firefox, Safari (ES6 support) |
| **Packet Capture** | Built-in Python fallback PCAP parser | Wireshark 4.x + TShark installed |
| **Managed Switch** | Optional unmanaged switch | Managed Switch with SNMPv2c enabled |

---

## 4. Step-by-Step Installation Guide

### Windows Installation

#### 1. Open PowerShell
Press `Win + X` and select **Terminal** or **Windows PowerShell**.

#### 2. Navigate to the Tool Directory
```powershell
cd D:\Network\electrical-interference-tool
```

#### 3. Create or Activate a Virtual Environment
If you already have a virtual environment in `D:\Network\.venv`:
```powershell
& D:\Network\.venv\Scripts\Activate.ps1
```
Or create a fresh virtual environment:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell displays an execution policy error, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

#### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

### Linux / macOS Installation

#### 1. Open Terminal and Navigate to Directory
```bash
cd /path/to/electrical-interference-tool
```

#### 2. Create and Activate Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 4. (Optional) Configure TShark Non-Root Permissions
On Debian/Ubuntu systems:
```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
```

---

## 5. Step-by-Step Execution Guide

### Starting the Server
Run the Flask server from your activated virtual environment:
```powershell
python app.py
```

Expected terminal startup output:
```text
2026-10-20 11:00:00 [INFO] emi_tool: Starting Electrical Interference Investigation Tool on http://127.0.0.1:5000
 * Serving Flask app 'app'
 * Debug mode: off
 * Running on all addresses (0.0.0.0:5000)
 * Running on http://127.0.0.1:5000
```

### Accessing the Web Interface
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

To stop the server at any time, press `Ctrl + C` in the terminal.

---

## 6. Complete Step-by-Step Investigation Walkthrough

Follow this 9-phase methodology when investigating suspected physical-layer interference or cable faults:

### Phase 1: Baseline Health Assessment (Test A)
1. **Prepare the Environment**: Ensure the suspected machinery (e.g., CNC mill, elevator motor, VFD, or arc welder) is **powered OFF**.
2. **Navigate to the Live Dashboard** (`/dashboard`).
3. **Configure the Target**: Enter your local Default Gateway (e.g., `192.168.10.1`) or local test server (`192.168.10.20`).
4. **Select Network Interface**: Choose your active physical Ethernet or Wi-Fi adapter from the dropdown.
5. **Set Duration**: Choose `5 Minutes (Standard)` or `15 Minutes (Extended)`.
6. **Click "Start Monitoring"**:
   - Observe the live RTT graph. A healthy wired link will show a flat line ($< 1.5\text{ ms}$) with $0.00\%$ packet loss.
   - Note the baseline average latency and ensure the **Link Status** indicator stays **GREEN**.

---

### Phase 2: Multi-Target Hop Isolation
To verify that packet loss is not caused by upstream ISP or WAN problems:
1. On the Live Dashboard, check the **"Enable Multi-Target Hop Isolation"** toggle.
2. Verify the 4 target fields:
   - **Default Gateway (Hop 1)**: `192.168.10.1` (Tests local cable + switch port).
   - **Local Switch Peer**: `192.168.10.20` (Tests purely local Layer 2 switching).
   - **DNS Server (Hop 2)**: `8.8.8.8` (Tests local routing + DNS lookup).
   - **Remote WAN Target**: `1.1.1.1` (Tests upstream Internet path).
3. **Evaluate the Results Table**:
   - **Local Cable Issue / EMI**: Hop 1 and Hop 2 both show latency spikes and loss.
   - **Upstream Internet Problem**: Hop 1 is completely clean ($0\%$ loss, $< 1.5\text{ ms}$), but Hop 3 shows high latency or loss. *This immediately rules out local EMI.*

---

### Phase 3: Controlled Active Equipment Observation (Test B)
1. **Activate Machinery**: Turn ON the suspected electrical equipment and operate it under normal working load.
2. **Safety Notice**: Keep all safety covers closed. Never touch electrical conduits or live wires.
3. **Start Monitoring**: Run a 5-minute monitoring cycle while the equipment cycles.
4. **Observe Anomalies**:
   - Check if latency spikes coincide with motor ramp-up or VFD pulse-width modulation (PWM) frequency switching.
   - Look at the **CRC/FCS Errors** KPI card. If the delta increments ($> 0$), physical frame corruption is actively taking place.
   - Look at the **Packet Loss** KPI card. If loss exceeds $2\%$, the indicator switches to **YELLOW** (Warning) or **RED** (Critical).

---

### Phase 4: Physical Cable Separation & Rerouting (Test C)
1. **Inspect Physical Path**: Follow the Ethernet cable path. Check if it is running parallel to 480V/240V AC power lines, resting on a motor housing, or sharing an electrical conduit tray.
2. **Reroute Cable**:
   - Safely unclip or move the Ethernet cable so it is separated by **at least 200 mm to 400 mm (8 to 16 inches)** from the power lines, according to **ANSI/TIA-568.0-D** standards.
   - If the cable must cross electrical lines, ensure it crosses at a **$90^\circ$ perpendicular angle**.
3. **Run Test C**: Monitor for 5 minutes with the equipment active.
   - If packet loss and latency return to normal baseline levels, this strongly supports an inductive/capacitive EMI coupling hypothesis.

---

### Phase 5: Shielded Cable Benchmark (Test D)
1. **Install Shielded Cable**: Replace the unshielded twisted-pair (UTP) cable with an industrial **Category 6A S/FTP (Screened/Foiled Twisted Pair)** cable.
2. **Grounding Check**: Ensure metal RJ45 shielded connectors are plugged into properly grounded shielded patch panels or switch ports.
3. **Run Test D**: Monitor for 5 minutes with the machinery active.
   - If performance remains flawless ($0\%$ loss, minimal jitter), you have verified the permanent technical remediation.

---

### Phase 6: Running the Scientific Correlation Engine
1. Navigate to the **EMI Investigation** tab (`/investigation`).
2. Log the incident metadata:
   - Location (e.g., `Production Floor Line 2`).
   - Cable Type (`Cat5e UTP`).
   - Length (e.g., `28.5 m`) and Distance to Source (e.g., `0.12 m`).
   - Source Type (`Variable Frequency Drive (VFD)`).
3. Review or adjust the measurements in the **Comparative Testing Matrix** (Tests A, B, C, D).
4. Click **"Run Scientific Correlation Engine"**:
   - The engine computes baseline deltas, variance ratios, and rule checks.
   - It outputs a **Diagnostic Conclusion** badge:
     - `Evidence Consistent with Physical-Layer Ethernet Impairment / Possible EMI`
     - `Evidence Consistent with Network Congestion / Queueing Delay`
     - `Upstream / WAN Routing Degradation (Local Cable Healthy)`
     - `Insufficient Evidence / Inconclusive`
   - It displays a **Confidence Score (0% to 100%)** based on the statistical sample size and whether Test C/D resolved the symptom.

---

### Phase 7: Wireshark & TShark Packet Dissection
1. In the **Live Dashboard**, scroll to the **Wireshark / TShark Packet Dissection** drawer.
2. Select your physical interface and duration (e.g., 60 seconds).
3. Click **"Start Capture"**. The background engine executes TShark in an isolated subprocess.
4. Click **"Stop Capture"** (or let it auto-terminate).
5. Review the summary metrics:
   - **TCP Retransmissions**: Frames dropped by the switch/NIC causing TCP to re-send packets.
   - **Duplicate ACKs**: Receiver signaling missing segments.
   - **TCP Resets (RST)**: Connection drops.
   - **DNS Failures**: Resolving hostnames failed.
6. *Offline Capture Analysis*: You can also drag and drop existing `.pcap` or `.pcapng` files for instant offline dissection.

---

### Phase 8: Managed Switch SNMP Hardware Counters
If you have a managed switch (Cisco, Juniper, HPE, Ubiquiti, Netgear, MikroTik):
1. The tool includes `SnmpSwitchMonitor` in `monitoring/snmp_monitor.py`.
2. Connect to the switch port via SNMPv2c:
   - Queries `dot3StatsFCSErrors` (`1.3.6.1.2.1.10.7.2.1.3`).
   - Queries `ifInErrors` (`1.3.6.1.2.1.2.2.1.14`).
   - Queries `ifInDiscards` (`1.3.6.1.2.1.2.2.1.13`).
3. This provides true port-level ASIC error counts that standard OS drivers discard.

---

### Phase 9: Exporting CSV & Generating Technical PDF Reports
1. Navigate to the **Reports & Export** page (`/reports`).
2. **Download CSV**: Click **"CSV"** to download the raw time-series dataset containing every sequence number, timestamp, RTT, and error flag.
3. **Download PDF Report**: Click **"PDF"** to compile an engineering report that includes:
   - Technical title and session parameters.
   - Network topology diagram and device IPs.
   - Statistical table: Sent, Received, Loss %, Mean, Min, Max, and Jitter.
   - Interface error and CRC/FCS delta changes.
   - Comparative Tests (A–D) matrix.
   - Wireshark dissection findings.
   - Root-cause classification with confidence score.
   - Actionable engineering recommendations (ANSI/TIA-568.0-D).
   - Electrical safety and measurement disclaimers.

---

## 7. Running Benchmark Demonstration Data

To inspect how the application evaluates an industrial incident without running a physical test:
1. Open the application in your browser.
2. In the top navigation bar, click the **"Load Benchmark Demo"** button.
3. The application will seed a benchmark dataset representing a **Manufacturing Plant VFD Spindle Motor** interference incident (Session ID #2).
4. Navigate to `/reports` and click **"PDF"** next to the benchmark session to view the formatted engineering output.

Alternatively, seed it from the command line:
```powershell
python sample_data/seed_demo_data.py
```

---

## 8. Running Automated Unit & Security Tests

Run the test suite using `pytest`:
```powershell
pytest tests/ -v
```

### What the Tests Verify:
- `test_calculate_statistics_nominal`: Confirms mathematical accuracy of mean, median, standard deviation, and RFC 3550 jitter.
- `test_detect_latency_spikes`: Verifies outlier detection using dynamic statistical thresholds ($Mean + 2.5 \times StdDev$).
- `test_compare_periods_degradation`: Confirms baseline vs. incident delta arithmetic.
- `test_correlation_insufficient_data`: Ensures the engine flags samples with $< 20$ packets as inconclusive.
- `test_correlation_physical_layer_crc_delta`: Confirms that hardware FCS increments route to the Physical-Layer/EMI diagnostic category.
- `test_correlation_hop_isolation_routing`: Verifies that a clean Hop 1 and degraded Hop 3 correctly classify as Upstream Routing.
- `test_validate_target_valid`: Validates legitimate IPv4, IPv6, and FQDN strings.
- `test_validate_target_injection_rejection`: Confirms that shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, whitespace) are blocked.
- `test_interface_counter_rollover_handling`: Confirms that adapter resets or counter wrap-arounds do not produce negative deltas.

---

## 9. Detailed Troubleshooting & Hardware Realities

### Q1: Why does the CRC/FCS counter show 0 even when ping packets are dropping?
**Hardware Reality:** Consumer network interface cards (NICs) perform hardware checksums on incoming Ethernet frames inside the physical MAC silicon. If a frame has bad FCS bits (due to EMI), the MAC chip **discards the frame immediately** without notifying the operating system kernel. Operating system tools (`netstat -e` or `ip -s link`) often show zero. To capture hardware CRC errors, you must query an **enterprise NIC with extended PHY statistics** (via Linux `ethtool -S`) or query the **connected managed switch port via SNMP**.

### Q2: Why does Windows ping show `time<1ms`?
Windows `ping.exe` uses integer milliseconds and represents round-trip times under 1 ms as `time<1ms`. The tool's parser detects this string and standardizes it to `0.5 ms` so statistical equations (mean, variance, jitter) compute accurately.

### Q3: TShark is not found or packet capture doesn't start.
1. Download and install Wireshark from [wireshark.org](https://www.wireshark.org/). Ensure **Npcap** is checked during installation.
2. Standard installation path on Windows: `C:\Program Files\Wireshark\tshark.exe`.
3. If installed in a non-standard location, add the folder to your Windows system `PATH`.
4. *Fallback Note:* The application does not require TShark to run. If absent, the built-in pure-Python PCAP parser handles offline files, and all ping and interface monitors continue working normally.

### Q4: Port 5000 is already in use.
Run the application on a different port:
```powershell
$env:PORT="5050"
python app.py
```
Or in Linux:
```bash
PORT=5050 python3 app.py
```

---

## 10. Application Security, Reliability & Compliance

- **No Shell Execution**: The application strictly avoids `shell=True`. All subprocess calls use tokenized argument lists (`subprocess.run(["ping", ...])`).
- **Input Validation**: Strict RFC regex filtering prevents command injection.
- **Standards Reference**:
  - **ANSI/TIA-568.0-D**: Generic Telecommunications Cabling for Customer Premises.
  - **ISO/IEC 11801**: Information Technology — Generic Cabling for Customer Premises.
  - **RFC 1213 / RFC 1643 / RFC 3635**: Management Information Base for Network Management of TCP/IP-based Internets: EtherLike-MIB.
  - **RFC 3550**: RTP: A Transport Protocol for Real-Time Applications (Jitter Calculations).
- **Safety First**: Non-invasive diagnostic architecture that strictly warns against opening electrical equipment or handling exposed wiring.
