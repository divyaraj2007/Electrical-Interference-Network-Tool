"""
Coordinated Network Test Suite Orchestrator for Sender and Receiver Agents.
Executes individual or composite network diagnostics with synchronized UTC timestamps.
"""

import sys
import time
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .security import (
    validate_ip_or_hostname, validate_port, validate_duration,
    validate_packet_size, validate_interval
)
from .ping_monitor import run_ping_series, test_mtu_fragmentation
from .traceroute import run_traceroute
from .dns_test import test_dns_resolution
from .iperf_manager import run_iperf_client
from .interface_monitor import AgentInterfaceMonitor
from .system_info import get_default_gateway, get_system_resource_usage

logger = logging.getLogger("agent.network_tests")


def test_tcp_connectivity(target: str, port: int = 80, timeout_sec: float = 3.0) -> Dict[str, Any]:
    """Test TCP 3-way handshake connectivity to a target host and port."""
    clean_target = validate_ip_or_hostname(target)
    port = validate_port(port)
    start_time = time.perf_counter()
    success = False
    error_msg = None

    try:
        sock = socket.create_connection((clean_target, port), timeout=timeout_sec)
        sock.close()
        success = True
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    except socket.timeout:
        elapsed_ms = round(timeout_sec * 1000.0, 2)
        error_msg = "TCP connection timed out"
    except ConnectionRefusedError:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        error_msg = "TCP connection actively refused (port closed)"
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        error_msg = str(e)

    return {
        "target": clean_target,
        "port": port,
        "success": success,
        "handshake_time_ms": elapsed_ms,
        "error": error_msg,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def test_udp_connectivity(target: str, port: int = 53, timeout_sec: float = 2.0) -> Dict[str, Any]:
    """Test UDP datagram delivery and socket responsiveness."""
    clean_target = validate_ip_or_hostname(target)
    port = validate_port(port)
    start_time = time.perf_counter()
    success = False
    error_msg = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        # Send minimal 16-byte UDP test probe
        sock.sendto(b"EMI_TEST_PROBE\x00\x00", (clean_target, port))
        sock.close()
        success = True
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        error_msg = str(e)

    return {
        "target": clean_target,
        "port": port,
        "success": success,
        "latency_ms": elapsed_ms,
        "error": error_msg,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


class NetworkTestOrchestrator:
    """Runs a requested suite of network tests and samples interface health throughout."""

    def __init__(self, interface_name: Optional[str] = None):
        self.interface_monitor = AgentInterfaceMonitor(interface_name=interface_name)

    def execute_test_suite(self,
                           target_ip: str,
                           test_modes: List[str],
                           duration_sec: int = 15,
                           packet_size: int = 64,
                           interval_sec: float = 0.5,
                           direction: str = "sender_to_receiver",
                           iperf_port: int = 5201,
                           role: str = "sender") -> Dict[str, Any]:
        """
        Execute requested tests sequentially or coordinated with synchronized UTC timestamps.
        """
        clean_target = validate_ip_or_hostname(target_ip)
        duration_sec = validate_duration(duration_sec, min_dur=1, max_dur=300)
        packet_size = validate_packet_size(packet_size, min_size=32, max_size=1500)
        interval_sec = validate_interval(interval_sec, min_int=0.05, max_int=5.0)

        utc_start = datetime.now(timezone.utc).isoformat()
        if_before = self.interface_monitor.capture_snapshot()
        sys_res_before = get_system_resource_usage()

        results: Dict[str, Any] = {
            "target": clean_target,
            "role": role,
            "direction": direction,
            "duration_sec": duration_sec,
            "packet_size_bytes": packet_size,
            "interval_sec": interval_sec,
            "start_time_utc": utc_start,
            "interface_initial": if_before,
            "metrics": {}
        }

        # Calculate probe count for ping tests
        probe_count = max(5, int(duration_sec / max(0.1, interval_sec)))

        # 1. ICMP Ping / RTT / Loss / Jitter to Target
        if "icmp_ping" in test_modes or "rtt" in test_modes or "jitter" in test_modes or "loss" in test_modes:
            logger.info("Executing ping series to target %s (%d probes)", clean_target, probe_count)
            ping_res = run_ping_series(
                target=clean_target,
                count=probe_count,
                interval_sec=interval_sec,
                packet_size=packet_size
            )
            results["metrics"]["ping"] = ping_res

        # 2. Ping to Default Gateway
        if "gateway_ping" in test_modes or "multi_target" in test_modes:
            gateway_ip = get_default_gateway()
            if gateway_ip:
                logger.info("Pinging default gateway %s", gateway_ip)
                gw_ping = run_ping_series(target=gateway_ip, count=5, interval_sec=0.2)
                results["metrics"]["gateway_ping"] = gw_ping
            else:
                results["metrics"]["gateway_ping"] = {"error": "Default gateway not discovered"}

        # 3. Ping to External IP (8.8.8.8)
        if "external_ping" in test_modes or "multi_target" in test_modes:
            logger.info("Pinging external IP 8.8.8.8")
            ext_ping = run_ping_series(target="8.8.8.8", count=5, interval_sec=0.2)
            results["metrics"]["external_ping"] = ext_ping

        # 4. DNS Test
        if "dns" in test_modes:
            logger.info("Executing DNS resolution test")
            results["metrics"]["dns"] = test_dns_resolution("google.com")

        # 5. Traceroute
        if "traceroute" in test_modes:
            logger.info("Executing traceroute to %s", clean_target)
            results["metrics"]["traceroute"] = run_traceroute(clean_target, max_hops=12)

        # 6. MTU & Fragmentation Test
        if "mtu" in test_modes:
            logger.info("Executing MTU fragmentation test to %s", clean_target)
            results["metrics"]["mtu"] = test_mtu_fragmentation(clean_target, start_size=1420, end_size=1500, step=20)

        # 7. TCP / UDP Throughput (iperf3 or socket engine)
        if "tcp_throughput" in test_modes or "throughput" in test_modes:
            # Check direction: if reverse, set reverse=True
            reverse_flag = (direction == "receiver_to_sender" and role == "sender") or \
                           (direction == "sender_to_receiver" and role == "receiver")
            logger.info("Executing TCP throughput test to %s:%d (reverse=%s)", clean_target, iperf_port, reverse_flag)
            tcp_res = run_iperf_client(
                target=clean_target,
                port=iperf_port,
                duration_sec=min(duration_sec, 20),
                protocol="tcp",
                reverse=reverse_flag
            )
            results["metrics"]["tcp_throughput"] = tcp_res

        if "udp_throughput" in test_modes:
            reverse_flag = (direction == "receiver_to_sender" and role == "sender") or \
                           (direction == "sender_to_receiver" and role == "receiver")
            logger.info("Executing UDP throughput test to %s:%d", clean_target, iperf_port)
            udp_res = run_iperf_client(
                target=clean_target,
                port=iperf_port,
                duration_sec=min(duration_sec, 15),
                protocol="udp",
                reverse=reverse_flag
            )
            results["metrics"]["udp_throughput"] = udp_res

        # 8. Post-test Interface and System Sampling
        if_after = self.interface_monitor.capture_snapshot()
        sys_res_after = get_system_resource_usage()
        utc_end = datetime.now(timezone.utc).isoformat()

        results["end_time_utc"] = utc_end
        results["interface_final"] = if_after
        results["interface_deltas"] = {
            "rx_errors_delta": if_after["rx_errors_delta"],
            "tx_errors_delta": if_after["tx_errors_delta"],
            "rx_drops_delta": if_after["rx_drops_delta"],
            "tx_drops_delta": if_after["tx_drops_delta"],
            "crc_delta": if_after["crc_delta"],
            "crc_supported": if_after["crc_supported"],
            "crc_display": if_after["crc_display"],
            "reset_detected": if_after["reset_detected"]
        }
        results["system_usage"] = {
            "cpu_before": sys_res_before["cpu_pct"],
            "cpu_after": sys_res_after["cpu_pct"],
            "mem_before": sys_res_before["mem_pct"],
            "mem_after": sys_res_after["mem_pct"]
        }

        return results
