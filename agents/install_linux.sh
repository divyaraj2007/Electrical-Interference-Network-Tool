#!/usr/bin/env bash
# ==============================================================================
# Linux Agent Installer (Ubuntu, Kali Linux, Debian, Fedora, Arch)
# Electrical Interference Investigation Tool - Device Testing Agents
# ==============================================================================

set -e

echo -e "\033[1;36m==========================================================\033[0m"
echo -e "\033[1;36m  Electrical Interference Investigation Agent Installer\033[0m"
echo -e "\033[1;36m  Platform: Ubuntu / Kali Linux / Debian / RHEL\033[0m"
echo -e "\033[1;36m==========================================================\033[0m"

# 1. Detect package manager
PKG_MANAGER=""
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
fi

# 2. Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "\033[1;33m[*] Python3 not found. Installing via system package manager...\033[0m"
    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv ethtool iproute2 iperf3
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        sudo dnf install -y python3 python3-pip ethtool iproute iperf3
    fi
fi

# 3. Optional tools check: ethtool & iperf3
if ! command -v ethtool &> /dev/null; then
    echo -e "\033[1;33m[i] Note: ethtool is recommended for hardware NIC CRC/FCS counter monitoring.\033[0m"
    if [ "$PKG_MANAGER" = "apt" ]; then
        echo "    Install with: sudo apt install -y ethtool iperf3"
    fi
fi

# 4. Setup Python Virtual Environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo -e "\033[1;33m[*] Creating Python virtual environment in $SCRIPT_DIR/.venv...\033[0m"
    python3 -m venv .venv || {
        echo "Error creating venv. If on Ubuntu/Debian: sudo apt install python3-venv"
        exit 1
    }
fi

echo -e "\033[1;33m[*] Installing agent dependencies...\033[0m"
"$SCRIPT_DIR/.venv/bin/python3" -m pip install --upgrade pip
"$SCRIPT_DIR/.venv/bin/python3" -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo -e "\033[1;32m==========================================================\033[0m"
echo -e "\033[1;32m  Agent Installation Completed Successfully!\033[0m"
echo -e "\033[1;32m==========================================================\033[0m"
echo -e "\033[1;37mTo run Device 1 (Sender):\033[0m"
echo -e "\033[1;36m  $SCRIPT_DIR/.venv/bin/python3 $SCRIPT_DIR/sender/sender_agent.py --server http://<FLASK_IP>:5000\033[0m"
echo ""
echo -e "\033[1;37mTo run Device 2 (Receiver):\033[0m"
echo -e "\033[1;36m  $SCRIPT_DIR/.venv/bin/python3 $SCRIPT_DIR/receiver/receiver_agent.py --server http://<FLASK_IP>:5000\033[0m"
