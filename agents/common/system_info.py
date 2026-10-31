"""
System & Network Hardware Information Collector.
Supports Windows 10/11, Ubuntu, Kali Linux, and standard Linux distributions.
Explicitly identifies whether CRC/FCS counters are supported by the underlying NIC/driver.
"""

import sys
import os
import platform
import socket
import subprocess
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("agent.system_info")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def get_operating_system_info() -> Dict[str, Any]:
    """Retrieve detailed operating system and platform metadata."""
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    machine = platform.machine()
    processor = platform.processor()

    distro_name = ""
    if os_name.lower() == "linux":
        try:
            # Check os-release for Ubuntu, Kali, Debian, etc.
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            distro_name = line.split("=", 1)[1].strip().strip('"')
                            break
        except Exception:
            pass
        if not distro_name:
            distro_name = f"Linux ({os_release})"
    elif os_name.lower() == "windows":
        distro_name = f"Windows {os_release} (Build {os_version})"
    else:
        distro_name = f"{os_name} {os_release}"

    return {
        "os_name": os_name,
        "os_release": os_release,
        "os_version": os_version,
        "distro_name": distro_name,
        "architecture": machine,
        "processor": processor,
        "hostname": socket.gethostname(),
        "python_version": platform.python_version()
    }


def get_system_resource_usage() -> Dict[str, float]:
    """Return CPU and Memory utilization percentages."""
    if not HAS_PSUTIL:
        return {"cpu_pct": 0.0, "mem_pct": 0.0}
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        return {"cpu_pct": float(cpu), "mem_pct": float(mem)}
    except Exception as e:
        logger.debug("Failed to read CPU/Mem: %s", e)
        return {"cpu_pct": 0.0, "mem_pct": 0.0}


def get_default_gateway() -> Optional[str]:
    """Find default gateway IP address across Windows and Linux."""
    try:
        if sys.platform.startswith("win"):
            proc = subprocess.run(
                ["route", "print", "0.0.0.0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3.0
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
        else:
            proc = subprocess.run(
                ["ip", "route", "show", "default"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3.0
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if "default" in parts and "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
    except Exception as e:
        logger.debug("Gateway lookup failed: %s", e)
    return None


def read_hardware_crc_linux(interface_name: str) -> Tuple[Optional[int], bool]:
    """
    Query Linux ethtool for hardware rx_crc_errors or rx_fcs_errors.
    Returns (error_count, is_supported_by_driver).
    If driver or NIC does not expose CRC counters, returns (None, False).
    """
    if not sys.platform.startswith("linux"):
        return None, False

    try:
        proc = subprocess.run(
            ["ethtool", "-S", interface_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2.0
        )
        if proc.returncode == 0:
            found_val = None
            for line in proc.stdout.splitlines():
                ll = line.lower()
                if any(k in ll for k in ["rx_crc_errors", "rx_fcs_errors", "crc_errors", "fcs_errors", "rx_crc", "rx_fcs"]):
                    parts = line.split(":")
                    if len(parts) == 2:
                        try:
                            found_val = int(parts[1].strip())
                            break
                        except ValueError:
                            pass
            if found_val is not None:
                return found_val, True
            # Command ran successfully, but NIC counters didn't list CRC
            return None, False
    except Exception as e:
        logger.debug("Linux ethtool CRC query failed for %s: %s", interface_name, e)

    return None, False


def read_hardware_crc_windows(interface_name: str) -> Tuple[Optional[int], bool, Dict[str, int]]:
    """
    Query Windows PowerShell Get-NetAdapterStatistics.
    Returns (crc_errors, is_supported, extra_stats).
    """
    extra = {"rx_discards": 0, "tx_discards": 0, "rx_errors": 0, "tx_errors": 0}
    if not sys.platform.startswith("win"):
        return None, False, extra

    try:
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
            timeout=3.5
        )
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                extra["rx_discards"] = int(data.get("ReceivedDiscardedPackets") or 0)
                extra["tx_discards"] = int(data.get("OutboundDiscardedPackets") or 0)
                extra["rx_errors"] = int(data.get("ReceivedPacketErrors") or 0)
                extra["tx_errors"] = int(data.get("OutboundPacketErrors") or 0)
                # Windows standard drivers do not expose raw PHY CRC/FCS counter via Get-NetAdapterStatistics
                return None, False, extra
    except Exception as e:
        logger.debug("Windows PowerShell stats query failed: %s", e)

    return None, False, extra


def get_interfaces_detail() -> List[Dict[str, Any]]:
    """
    Enumerate all network interfaces with full addressing, speed, status,
    and platform-specific error counters with explicit CRC support detection.
    """
    if not HAS_PSUTIL:
        return []

    interfaces = []
    io_counters = psutil.net_io_counters(pernic=True)
    if_stats = psutil.net_if_stats()
    if_addrs = psutil.net_if_addrs()

    for name, stats in if_stats.items():
        io = io_counters.get(name)
        addrs = if_addrs.get(name, [])

        ipv4_addr = None
        ipv6_addr = None
        mac_addr = None
        netmask = None

        for addr in addrs:
            fam = getattr(addr.family, "name", str(addr.family))
            if fam == "AF_INET" and not ipv4_addr:
                ipv4_addr = addr.address
                netmask = addr.netmask
            elif fam == "AF_INET6" and not ipv6_addr:
                ipv6_addr = addr.address
            elif fam in ("AF_LINK", "AF_PACKET") or "17" in str(addr.family):
                mac_addr = addr.address

        is_physical = not any(v in name.lower() for v in ["loopback", "pseudo", "teredo", "isatap", "vethernet", "docker", "vbox"])

        rx_err = io.errin if io else 0
        tx_err = io.errout if io else 0
        rx_drop = io.dropin if io else 0
        tx_drop = io.dropout if io else 0

        crc_val: Optional[int] = None
        crc_supported: bool = False

        if sys.platform.startswith("linux"):
            crc_val, crc_supported = read_hardware_crc_linux(name)
        elif sys.platform.startswith("win"):
            crc_val, crc_supported, win_extra = read_hardware_crc_windows(name)
            rx_drop = max(rx_drop, win_extra["rx_discards"])
            tx_drop = max(tx_drop, win_extra["tx_discards"])
            rx_err = max(rx_err, win_extra["rx_errors"])
            tx_err = max(tx_err, win_extra["tx_errors"])

        duplex_str = str(stats.duplex).split(".")[-1] if stats.duplex else "UNKNOWN"

        interfaces.append({
            "name": name,
            "is_up": bool(stats.isup),
            "speed_mbps": int(stats.speed) if stats.speed and stats.speed > 0 else 0,
            "duplex": duplex_str,
            "mtu": stats.mtu or 1500,
            "ipv4": ipv4_addr,
            "ipv6": ipv6_addr,
            "mac": mac_addr,
            "netmask": netmask,
            "is_physical": is_physical,
            "bytes_sent": io.bytes_sent if io else 0,
            "bytes_recv": io.bytes_recv if io else 0,
            "packets_sent": io.packets_sent if io else 0,
            "packets_recv": io.packets_recv if io else 0,
            "rx_errors": rx_err,
            "tx_errors": tx_err,
            "rx_drops": rx_drop,
            "tx_drops": tx_drop,
            "crc_fcs_errors": crc_val if crc_supported else None,
            "crc_supported": crc_supported,
            "crc_display": str(crc_val) if crc_supported else "Unsupported by OS/driver"
        })

    # Prioritize active physical interfaces with IPv4
    interfaces.sort(key=lambda x: (x["is_up"], x["ipv4"] is not None, x["is_physical"]), reverse=True)
    return interfaces


def get_primary_interface() -> Optional[Dict[str, Any]]:
    """Determine the primary outbound network interface."""
    interfaces = get_interfaces_detail()
    for iface in interfaces:
        if iface["is_up"] and iface["ipv4"] and not iface["ipv4"].startswith("127."):
            return iface
    return interfaces[0] if interfaces else None
