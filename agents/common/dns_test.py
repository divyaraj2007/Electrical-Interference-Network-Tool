"""
DNS Resolution and Latency Diagnostic Module.
Measures DNS lookup time, resolves IP records, and verifies resolver health.
"""

import socket
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("agent.dns_test")


def test_dns_resolution(hostname: str = "google.com", server: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform DNS resolution and measure lookup latency in milliseconds.
    """
    clean_host = hostname.strip()
    start_time = time.perf_counter()
    resolved_ips: List[str] = []
    success = False
    error_msg = None

    try:
        # Standard socket resolution
        addr_info = socket.getaddrinfo(clean_host, None)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        for item in addr_info:
            ip = item[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        success = len(resolved_ips) > 0
    except socket.gaierror as ge:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        error_msg = f"DNS resolution failed: {ge}"
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        error_msg = str(e)

    return {
        "hostname": clean_host,
        "success": success,
        "dns_server": server or "system_default",
        "latency_ms": elapsed_ms,
        "resolved_ips": resolved_ips,
        "error": error_msg,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
