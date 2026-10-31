"""
Cross-Platform ICMP Ping, Jitter, and MTU Fragmentation Testing Module.
Calculates minimum, maximum, average RTT, packet loss, and RFC 3550 standard jitter.
"""

import sys
import re
import time
import subprocess
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from .security import validate_ip_or_hostname, validate_duration, validate_interval, validate_packet_size

logger = logging.getLogger("agent.ping_monitor")


def ping_single_probe(target: str, timeout_sec: float = 2.0, packet_size: int = 64) -> Dict[str, Any]:
    """
    Execute a single ICMP echo probe using the OS ping binary.
    Parses RTT directly and reports success/failure with millisecond precision.
    """
    clean_target = validate_ip_or_hostname(target)
    start_time = time.time()
    rtt_ms: Optional[float] = None
    success = False
    error_msg = None

    if sys.platform.startswith("win"):
        # Windows ping flags: -n 1 (count 1), -w timeout_ms, -l buffer_size
        timeout_ms = int(timeout_sec * 1000)
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), "-l", str(packet_size), clean_target]
    else:
        # Linux ping flags: -c 1 (count 1), -W timeout_sec, -s payload_size
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout_sec))), "-s", str(packet_size), clean_target]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec + 1.5
        )
        output = proc.stdout

        if proc.returncode == 0:
            # Parse Windows output: "time=12ms" or "time<1ms"
            # Parse Linux output: "time=12.3 ms"
            match = re.search(r"time[<=]([0-9.]+)\s*ms", output, re.IGNORECASE)
            if match:
                rtt_ms = float(match.group(1))
                success = True
            elif "<1ms" in output:
                rtt_ms = 0.5
                success = True
            else:
                rtt_ms = max(0.1, round((time.time() - start_time) * 1000, 2))
                success = True
        else:
            if "timed out" in output.lower() or "unreachable" in output.lower():
                error_msg = "Request timed out or destination host unreachable"
            else:
                error_msg = proc.stderr.strip() or "Ping probe failed"
    except subprocess.TimeoutExpired:
        error_msg = "Probe timed out"
    except Exception as e:
        error_msg = str(e)

    return {
        "target": clean_target,
        "success": success,
        "rtt_ms": rtt_ms,
        "error_msg": error_msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def calculate_rfc3550_jitter(rtt_samples: List[float]) -> float:
    """
    Calculate interarrival jitter based on RFC 3550 algorithm:
    J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
    """
    if len(rtt_samples) < 2:
        return 0.0

    jitter = 0.0
    for i in range(1, len(rtt_samples)):
        diff = abs(rtt_samples[i] - rtt_samples[i - 1])
        jitter += (diff - jitter) / 16.0

    return round(jitter, 3)


def run_ping_series(target: str,
                     count: int = 10,
                     interval_sec: float = 0.5,
                     packet_size: int = 64,
                     timeout_sec: float = 2.0) -> Dict[str, Any]:
    """
    Run a sequence of ping probes and calculate comprehensive RTT statistics,
    packet loss percentage, and jitter.
    """
    clean_target = validate_ip_or_hostname(target)
    samples: List[float] = []
    sent = 0
    received = 0
    lost = 0

    probes = []
    for seq in range(count):
        sent += 1
        res = ping_single_probe(clean_target, timeout_sec=timeout_sec, packet_size=packet_size)
        res["sequence"] = seq + 1
        probes.append(res)

        if res["success"] and res["rtt_ms"] is not None:
            received += 1
            samples.append(res["rtt_ms"])
        else:
            lost += 1

        if seq < count - 1 and interval_sec > 0:
            time.sleep(interval_sec)

    loss_pct = round((lost / sent) * 100.0, 2) if sent > 0 else 0.0
    min_rtt = round(min(samples), 3) if samples else 0.0
    max_rtt = round(max(samples), 3) if samples else 0.0
    avg_rtt = round(sum(samples) / len(samples), 3) if samples else 0.0
    jitter = calculate_rfc3550_jitter(samples)

    return {
        "target": clean_target,
        "packets_sent": sent,
        "packets_received": received,
        "packets_lost": lost,
        "loss_pct": loss_pct,
        "min_rtt_ms": min_rtt,
        "max_rtt_ms": max_rtt,
        "avg_rtt_ms": avg_rtt,
        "jitter_ms": jitter,
        "samples": samples,
        "probes": probes
    }


def test_mtu_fragmentation(target: str, start_size: int = 1400, end_size: int = 1500, step: int = 10) -> Dict[str, Any]:
    """
    Test Maximum Transmission Unit (MTU) and packet fragmentation boundaries.
    Sets the 'Don't Fragment' (DF) bit.
    Windows: ping -f -l <size> <target>
    Linux: ping -M do -s <size> <target>
    """
    clean_target = validate_ip_or_hostname(target)
    max_unfragmented = None
    results = []

    for size in range(start_size, end_size + 1, step):
        if sys.platform.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", "1500", "-f", "-l", str(size), clean_target]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(size), clean_target]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3.0
            )
            out = proc.stdout.lower()

            # Check if packet fragmented or failed DF
            is_fragmented = ("packet needs to be fragmented" in out or
                             "frag needed" in out or
                             "message too long" in out or
                             "fragmentation needed" in out)

            success = (proc.returncode == 0) and not is_fragmented

            if success:
                max_unfragmented = size
                results.append({"payload_size": size, "fragmented": False, "success": True})
            else:
                results.append({"payload_size": size, "fragmented": True, "success": False})
                if is_fragmented:
                    # Once fragmentation occurs, subsequent larger packets will also fragment
                    break
        except Exception as e:
            results.append({"payload_size": size, "fragmented": True, "success": False, "error": str(e)})

    # Estimated IP MTU = unfragmented payload + 20 (IPv4 header) + 8 (ICMP header)
    estimated_mtu = (max_unfragmented + 28) if max_unfragmented is not None else 1500

    return {
        "target": clean_target,
        "max_unfragmented_payload": max_unfragmented,
        "estimated_path_mtu": estimated_mtu,
        "tests": results
    }
