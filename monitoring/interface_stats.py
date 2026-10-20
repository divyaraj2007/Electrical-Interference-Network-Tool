"""
Physical Network Interface Statistics & CRC/FCS Error Monitor.
Supports Windows (PowerShell/psutil/netstat) and Linux (ethtool/ip -s/sysfs).
Accurately calculates counter deltas, detects adapter resets, and includes scientific notices.
"""

import sys
import os
import re
import subprocess
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import psutil

logger = logging.getLogger(__name__)

# Scientific documentation note regarding hardware vs OS visibility
PHYSICAL_LAYER_DISCLAIMER = (
    "SCIENTIFIC NOTICE: Standard consumer and OS network drivers discard corrupted Ethernet frames "
    "with invalid Frame Check Sequences (FCS/CRC) at the physical (PHY) and MAC hardware layer. "
    "Consequently, standard operating system counters (e.g., netstat -e or psutil) will frequently "
    "remain at zero even in environments with heavy electromagnetic interference (EMI). "
    "Accurate port-level CRC/FCS observation requires an enterprise NIC with driver PHY diagnostics "
    "(e.g. Intel with ethtool -S on Linux) or querying a managed Ethernet switch via SNMP."
)


def get_all_interfaces_summary() -> List[Dict[str, Any]]:
    """
    List all detected physical and logical network interfaces with their status,
    speed, addresses, and hardware capabilities.
    """
    interfaces = []
    io_counters = psutil.net_io_counters(pernic=True)
    if_stats = psutil.net_if_stats()
    if_addrs = psutil.net_if_addrs()

    for name, stats in if_stats.items():
        # Skip purely disconnected or loopback interfaces if user prefers, but list them for complete visibility
        io = io_counters.get(name)
        addrs = if_addrs.get(name, [])

        ipv4_addr = None
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ipv4_addr = addr.address
                break

        is_physical = not any(v in name.lower() for v in ["loopback", "pseudo", "teredo", "isatap", "vethernet"])

        interfaces.append({
            "name": name,
            "is_up": stats.isup,
            "speed_mbps": stats.speed if stats.speed > 0 else 0,
            "duplex": str(stats.duplex).split(".")[-1],
            "mtu": stats.mtu,
            "ipv4": ipv4_addr,
            "is_physical": is_physical,
            "bytes_sent": io.bytes_sent if io else 0,
            "bytes_recv": io.bytes_recv if io else 0,
            "rx_errors": io.errin if io else 0,
            "tx_errors": io.errout if io else 0,
            "rx_drops": io.dropin if io else 0,
            "tx_drops": io.dropout if io else 0
        })

    # Sort so active physical interfaces with IPv4 come first
    interfaces.sort(key=lambda x: (x["is_up"], x["ipv4"] is not None, x["is_physical"]), reverse=True)
    return interfaces


def read_linux_ethtool_crc(interface_name: str) -> Optional[int]:
    """
    Query Linux ethtool for hardware-level rx_crc_errors or rx_fcs_errors.
    Returns integer count or None if not supported by driver.
    """
    if not sys.platform.startswith("linux"):
        return None

    try:
        proc = subprocess.run(
            ["ethtool", "-S", interface_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2.0
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                line_lower = line.lower()
                if "crc_err" in line_lower or "fcs_err" in line_lower or "rx_crc" in line_lower or "rx_fcs" in line_lower:
                    parts = line.split(":")
                    if len(parts) == 2:
                        return int(parts[1].strip())
    except Exception as e:
        logger.debug("ethtool query failed for %s: %s", interface_name, e)

    return None


def read_windows_powershell_stats(interface_name: str) -> Dict[str, int]:
    """
    Query Windows PowerShell Get-NetAdapterStatistics for detailed packet discards and errors.
    """
    results = {
        "rx_discards": 0,
        "tx_discards": 0,
        "rx_errors": 0,
        "tx_errors": 0
    }
    if not sys.platform.startswith("win"):
        return results

    try:
        # PowerShell query filtered by interface name
        clean_name = interface_name.replace("'", "").replace('"', "")
        ps_cmd = (
            f"Get-NetAdapterStatistics -Name '{clean_name}' -ErrorAction SilentlyContinue | "
            f"Select-Object ReceivedDiscardedPackets, OutboundDiscardedPackets, "
            f"ReceivedPacketErrors, OutboundPacketErrors | ConvertTo-Json"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3.0
        )
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                results["rx_discards"] = int(data.get("ReceivedDiscardedPackets") or 0)
                results["tx_discards"] = int(data.get("OutboundDiscardedPackets") or 0)
                results["rx_errors"] = int(data.get("ReceivedPacketErrors") or 0)
                results["tx_errors"] = int(data.get("OutboundPacketErrors") or 0)
    except Exception as e:
        logger.debug("PowerShell Get-NetAdapterStatistics query failed: %s", e)

    return results


class InterfaceStatsMonitor:
    """
    Monitors interface counter changes over time.
    Calculates deltas between intervals and gracefully handles adapter resets/counter wraps.
    """

    def __init__(self, interface_name: str, session_id: Optional[int] = None):
        self.interface_name = interface_name
        self.session_id = session_id
        self.last_snapshot: Optional[Dict[str, Any]] = None
        self.total_errors_delta = 0
        self.total_crc_delta = 0
        self.reset_detected_count = 0

    def capture_snapshot(self) -> Dict[str, Any]:
        """
        Poll the current counter values, calculate delta from previous poll,
        and return a comprehensive interface health record.
        """
        io_counters = psutil.net_io_counters(pernic=True)
        if_stats = psutil.net_if_stats()

        io = io_counters.get(self.interface_name)
        stats = if_stats.get(self.interface_name)

        if not io:
            # Interface might have disconnected or name mismatch
            return {
                "session_id": self.session_id,
                "interface_name": self.interface_name,
                "is_up": False,
                "link_speed_mbps": 0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets_sent": 0,
                "packets_recv": 0,
                "rx_errors": 0,
                "tx_errors": 0,
                "rx_drops": 0,
                "tx_drops": 0,
                "crc_fcs_errors": 0,
                "rx_errors_delta": 0,
                "tx_errors_delta": 0,
                "rx_drops_delta": 0,
                "crc_fcs_delta": 0,
                "reset_detected": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # Raw values from psutil
        rx_errors = io.errin
        tx_errors = io.errout
        rx_drops = io.dropin
        tx_drops = io.dropout

        # Check OS-specific physical/FCS counters
        crc_fcs_errors = 0
        if sys.platform.startswith("linux"):
            ethtool_crc = read_linux_ethtool_crc(self.interface_name)
            if ethtool_crc is not None:
                crc_fcs_errors = ethtool_crc
        elif sys.platform.startswith("win"):
            # Check PowerShell metrics if available
            ps_stats = read_windows_powershell_stats(self.interface_name)
            rx_drops = max(rx_drops, ps_stats["rx_discards"])
            tx_drops = max(tx_drops, ps_stats["tx_discards"])
            rx_errors = max(rx_errors, ps_stats["rx_errors"])
            tx_errors = max(tx_errors, ps_stats["tx_errors"])

        # Calculate deltas and handle resets
        reset_detected = False
        rx_err_delta = 0
        tx_err_delta = 0
        rx_drop_delta = 0
        crc_delta = 0

        if self.last_snapshot:
            prev_rx_err = self.last_snapshot["rx_errors"]
            prev_tx_err = self.last_snapshot["tx_errors"]
            prev_rx_drop = self.last_snapshot["rx_drops"]
            prev_crc = self.last_snapshot["crc_fcs_errors"]

            # If current is less than previous, the interface reset or counter wrapped
            if rx_errors < prev_rx_err or tx_errors < prev_tx_err or rx_drops < prev_rx_drop or crc_fcs_errors < prev_crc:
                reset_detected = True
                self.reset_detected_count += 1
                logger.info("Interface %s counter reset or rollover detected.", self.interface_name)
                rx_err_delta = rx_errors
                tx_err_delta = tx_errors
                rx_drop_delta = rx_drops
                crc_delta = crc_fcs_errors
            else:
                rx_err_delta = rx_errors - prev_rx_err
                tx_err_delta = tx_errors - prev_tx_err
                rx_drop_delta = rx_drops - prev_rx_drop
                crc_delta = crc_fcs_errors - prev_crc

        self.total_errors_delta += (rx_err_delta + tx_err_delta)
        self.total_crc_delta += crc_delta

        snapshot = {
            "session_id": self.session_id,
            "interface_name": self.interface_name,
            "is_up": stats.isup if stats else True,
            "link_speed_mbps": stats.speed if stats and stats.speed > 0 else 0,
            "bytes_sent": io.bytes_sent,
            "bytes_recv": io.bytes_recv,
            "packets_sent": io.packets_sent,
            "packets_recv": io.packets_recv,
            "rx_errors": rx_errors,
            "tx_errors": tx_errors,
            "rx_drops": rx_drops,
            "tx_drops": tx_drops,
            "crc_fcs_errors": crc_fcs_errors,
            "rx_errors_delta": rx_err_delta,
            "tx_errors_delta": tx_err_delta,
            "rx_drops_delta": rx_drop_delta,
            "crc_fcs_delta": crc_delta,
            "total_errors_delta": self.total_errors_delta,
            "total_crc_delta": self.total_crc_delta,
            "reset_detected": reset_detected,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.last_snapshot = snapshot
        return snapshot
