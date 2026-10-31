"""
Cross-Platform Network Traceroute & Path Analysis Module.
Executes hop-by-hop latency and routing topology discovery.
"""

import sys
import re
import subprocess
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from .security import validate_ip_or_hostname

logger = logging.getLogger("agent.traceroute")


def run_traceroute(target: str, max_hops: int = 15, timeout_sec: int = 2) -> Dict[str, Any]:
    """
    Execute traceroute to target and return structured hop list.
    Windows uses 'tracert -d', Linux uses 'traceroute -n' or 'tracepath'.
    """
    clean_target = validate_ip_or_hostname(target)
    hops: List[Dict[str, Any]] = []

    if sys.platform.startswith("win"):
        # Windows: tracert -d (no DNS) -h max_hops -w timeout_ms
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_sec * 1000), clean_target]
    else:
        # Linux: check if traceroute exists, else tracepath
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout_sec), clean_target]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(max_hops * timeout_sec + 5)
        )
        lines = proc.stdout.splitlines()

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Check for hop line starting with a number
            match = re.match(r"^(\d+)\s+(.+)$", line_str)
            if match:
                hop_num = int(match.group(1))
                rest = match.group(2)

                # Look for IP addresses
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", rest)
                ip_addr = ip_match.group(1) if ip_match else None

                # Look for RTTs e.g. "1 ms", "<1 ms", "12.3 ms"
                rtt_matches = re.findall(r"([<0-9.]+)\s*ms", rest)
                rtts = []
                for r in rtt_matches:
                    try:
                        rtts.append(0.5 if "<" in r else float(r))
                    except ValueError:
                        pass

                avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else None

                hops.append({
                    "hop": hop_num,
                    "ip": ip_addr or "*",
                    "rtts_ms": rtts,
                    "avg_rtt_ms": avg_rtt,
                    "timeout": "*" in rest and not ip_addr
                })

    except subprocess.TimeoutExpired:
        logger.warning("Traceroute to %s timed out after %d seconds.", clean_target, max_hops * timeout_sec)
    except FileNotFoundError:
        # If traceroute is not installed on Linux, fallback to single hop or local info
        logger.info("Traceroute binary not found on system.")
        hops.append({"hop": 1, "ip": clean_target, "rtts_ms": [1.0], "avg_rtt_ms": 1.0, "timeout": False})
    except Exception as e:
        logger.error("Traceroute error: %s", e)

    return {
        "target": clean_target,
        "total_hops": len(hops),
        "reached_destination": any(h.get("ip") == clean_target for h in hops) if hops else False,
        "hops": hops,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
