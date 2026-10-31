"""
Network Interface Statistics & Physical Counter Monitor for Agents.
Tracks deltas, detects adapter resets, and handles hardware counters safely.
"""

import sys
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from .system_info import get_interfaces_detail

logger = logging.getLogger("agent.interface_monitor")


class AgentInterfaceMonitor:
    """Monitors a specified network interface on the device."""

    def __init__(self, interface_name: Optional[str] = None):
        self.interface_name = interface_name
        self.last_snapshot: Optional[Dict[str, Any]] = None
        self.total_errors_delta = 0
        self.total_drops_delta = 0
        self.total_crc_delta = 0
        self.resets_detected = 0

    def capture_snapshot(self) -> Dict[str, Any]:
        """Sample current interface counters and calculate deltas."""
        interfaces = get_interfaces_detail()
        target_if = None

        if self.interface_name:
            for iface in interfaces:
                if iface["name"].lower() == self.interface_name.lower():
                    target_if = iface
                    break

        if not target_if:
            # Fallback to the first active interface
            for iface in interfaces:
                if iface["is_up"] and iface["ipv4"] and not iface["ipv4"].startswith("127."):
                    target_if = iface
                    self.interface_name = iface["name"]
                    break

        if not target_if and interfaces:
            target_if = interfaces[0]
            self.interface_name = target_if["name"]

        if not target_if:
            return {
                "interface_name": self.interface_name or "None",
                "is_up": False,
                "link_speed_mbps": 0,
                "duplex": "UNKNOWN",
                "bytes_sent": 0, "bytes_recv": 0,
                "packets_sent": 0, "packets_recv": 0,
                "rx_errors": 0, "tx_errors": 0,
                "rx_drops": 0, "tx_drops": 0,
                "crc_fcs_errors": None,
                "crc_supported": False,
                "crc_display": "Unsupported by OS/driver",
                "rx_errors_delta": 0, "tx_errors_delta": 0,
                "rx_drops_delta": 0, "crc_delta": 0,
                "reset_detected": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        rx_err = target_if["rx_errors"]
        tx_err = target_if["tx_errors"]
        rx_drop = target_if["rx_drops"]
        tx_drop = target_if["tx_drops"]
        crc_val = target_if["crc_fcs_errors"]
        crc_supp = target_if["crc_supported"]

        rx_err_delta = 0
        tx_err_delta = 0
        rx_drop_delta = 0
        tx_drop_delta = 0
        crc_delta = 0
        reset_detected = False

        if self.last_snapshot:
            prev_rx_err = self.last_snapshot["rx_errors"]
            prev_tx_err = self.last_snapshot["tx_errors"]
            prev_rx_drop = self.last_snapshot["rx_drops"]
            prev_tx_drop = self.last_snapshot["tx_drops"]
            prev_crc = self.last_snapshot.get("crc_fcs_errors")

            # Check if counters wrapped or interface was reset
            if rx_err < prev_rx_err or tx_err < prev_tx_err or rx_drop < prev_rx_drop or tx_drop < prev_tx_drop:
                reset_detected = True
                self.resets_detected += 1
                rx_err_delta = rx_err
                tx_err_delta = tx_err
                rx_drop_delta = rx_drop
                tx_drop_delta = tx_drop
                if crc_supp and crc_val is not None:
                    crc_delta = crc_val
            else:
                rx_err_delta = rx_err - prev_rx_err
                tx_err_delta = tx_err - prev_tx_err
                rx_drop_delta = rx_drop - prev_rx_drop
                tx_drop_delta = tx_drop - prev_tx_drop
                if crc_supp and crc_val is not None and prev_crc is not None:
                    crc_delta = max(0, crc_val - prev_crc)

        self.total_errors_delta += (rx_err_delta + tx_err_delta)
        self.total_drops_delta += (rx_drop_delta + tx_drop_delta)
        self.total_crc_delta += crc_delta

        snapshot = {
            "interface_name": target_if["name"],
            "is_up": target_if["is_up"],
            "link_speed_mbps": target_if["speed_mbps"],
            "duplex": target_if["duplex"],
            "mtu": target_if["mtu"],
            "ipv4": target_if["ipv4"],
            "bytes_sent": target_if["bytes_sent"],
            "bytes_recv": target_if["bytes_recv"],
            "packets_sent": target_if["packets_sent"],
            "packets_recv": target_if["packets_recv"],
            "rx_errors": rx_err,
            "tx_errors": tx_err,
            "rx_drops": rx_drop,
            "tx_drops": tx_drop,
            "crc_fcs_errors": crc_val,
            "crc_supported": crc_supp,
            "crc_display": target_if["crc_display"],
            "rx_errors_delta": rx_err_delta,
            "tx_errors_delta": tx_err_delta,
            "rx_drops_delta": rx_drop_delta,
            "tx_drops_delta": tx_drop_delta,
            "crc_delta": crc_delta,
            "total_errors_delta": self.total_errors_delta,
            "total_drops_delta": self.total_drops_delta,
            "total_crc_delta": self.total_crc_delta,
            "reset_detected": reset_detected,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.last_snapshot = snapshot
        return snapshot
