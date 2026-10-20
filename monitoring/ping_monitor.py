"""
Ping Monitoring Module for Electrical Interference Investigation Tool.
Executes real network ICMP pings across Windows and Linux platforms safely without shell injection.
Supports single-target, continuous, 11-hour investigations, and multi-target isolation.
"""

import sys
import os
import re
import time
import subprocess
import threading
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)

# RFC-compliant target validation regex (IPv4, IPv6, or Hostname)
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_REGEX = re.compile(r"^([0-9a-fA-F]{1,4}:){1,7}:?([0-9a-fA-F]{1,4}|:)?$")
HOSTNAME_REGEX = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def validate_target(target: str) -> str:
    """
    Validate target to prevent command injection and ensure standard IP or hostname.
    Raises ValueError on invalid target.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string.")
    
    clean_target = target.strip()
    
    # Explicitly disallow shell metacharacters and whitespaces
    if any(c in clean_target for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", " "]):
        raise ValueError("Target contains illegal characters.")

    if not (IPV4_REGEX.match(clean_target) or IPV6_REGEX.match(clean_target) or HOSTNAME_REGEX.match(clean_target)):
        raise ValueError(f"Invalid IP address or hostname format: '{clean_target}'")

    return clean_target


@dataclass
class PingResult:
    """Represents a single ping observation."""
    target: str
    sequence: int
    rtt_ms: Optional[float]
    success: bool
    timeout: bool
    error_msg: Optional[str]
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    target_role: str = "target"


def ping_single(target: str, timeout_sec: float = 2.0, target_role: str = "target", sequence: int = 1) -> PingResult:
    """
    Execute a single real system ICMP ping and parse the round-trip time.
    Uses safe subprocess execution with direct argument lists (never shell=True).
    """
    clean_target = validate_target(target)
    is_windows = sys.platform.startswith("win")

    if is_windows:
        # Windows ping: -n 1 (1 packet), -w timeout_ms
        timeout_ms = max(500, int(timeout_sec * 1000))
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), clean_target]
    else:
        # Linux/macOS ping: -c 1 (1 packet), -W timeout_sec
        timeout_w = max(1, int(timeout_sec))
        cmd = ["ping", "-c", "1", "-W", str(timeout_w), clean_target]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec + 2.0
        )
        stdout = proc.stdout
        stderr = proc.stderr

        # Check return code and output strings
        if proc.returncode == 0:
            # Parse round-trip time
            rtt_ms = None
            if is_windows:
                # Matches: "time<1ms" or "time=14ms" or "time=14.5ms"
                match = re.search(r"time(?:=|<)\s*(\d+(?:\.\d+)?)\s*ms", stdout, re.IGNORECASE)
                if match:
                    rtt_str = match.group(1)
                    if "time<" in stdout.lower() and float(rtt_str) == 1:
                        rtt_ms = 0.5  # Sub-millisecond round trip
                    else:
                        rtt_ms = float(rtt_str)
            else:
                # Matches Linux: "time=14.2 ms" or "time=0.456 ms"
                match = re.search(r"time=(\d+(?:\.\d+)?)\s*ms", stdout, re.IGNORECASE)
                if match:
                    rtt_ms = float(match.group(1))

            if rtt_ms is not None:
                return PingResult(
                    target=clean_target,
                    sequence=sequence,
                    rtt_ms=round(rtt_ms, 2),
                    success=True,
                    timeout=False,
                    error_msg=None,
                    target_role=target_role
                )

        # Handle failure cases
        is_timeout = "request timed out" in stdout.lower() or "100% packet loss" in stdout.lower() or "100% loss" in stdout.lower()
        err_line = stderr.strip() if stderr.strip() else ("Request timed out" if is_timeout else "Host unreachable or dropped")

        return PingResult(
            target=clean_target,
            sequence=sequence,
            rtt_ms=None,
            success=False,
            timeout=is_timeout,
            error_msg=err_line[:120],
            target_role=target_role
        )

    except subprocess.TimeoutExpired:
        return PingResult(
            target=clean_target,
            sequence=sequence,
            rtt_ms=None,
            success=False,
            timeout=True,
            error_msg="Ping subprocess execution timed out",
            target_role=target_role
        )
    except Exception as e:
        return PingResult(
            target=clean_target,
            sequence=sequence,
            rtt_ms=None,
            success=False,
            timeout=False,
            error_msg=str(e)[:120],
            target_role=target_role
        )


class PingMonitor:
    """
    Background worker that continuously monitors one or multiple network targets.
    Maintains real-time in-memory rolling statistics, respects duration/packet limits,
    and supports an instant graceful stop without leaving zombie processes.
    """

    def __init__(self, session_id: int, targets: List[Dict[str, str]],
                 interval_sec: float = 1.0, duration_sec: Optional[int] = 60,
                 packet_limit: Optional[int] = None, timeout_sec: float = 2.0,
                 on_result_callback=None):
        """
        targets: List of dicts, e.g. [{"target": "192.168.1.1", "role": "gateway"}, ...]
        interval_sec: Seconds between pings (min 0.1s)
        duration_sec: Session duration limit in seconds (39600 for 11h, or None for continuous until manual stop)
        packet_limit: Maximum packets to send per target (or None)
        """
        self.session_id = session_id
        self.targets = targets
        self.interval_sec = max(0.1, interval_sec)
        self.duration_sec = duration_sec
        self.packet_limit = packet_limit
        self.timeout_sec = max(0.5, timeout_sec)
        self.on_result_callback = on_result_callback

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.is_running = False

        # Metrics per target: target -> metrics dict
        self.stats: Dict[str, Dict[str, Any]] = {}
        for item in targets:
            tgt = item["target"]
            self.stats[tgt] = {
                "target": tgt,
                "role": item.get("role", "target"),
                "packets_sent": 0,
                "packets_received": 0,
                "packets_lost": 0,
                "loss_pct": 0.0,
                "current_rtt": None,
                "avg_rtt": 0.0,
                "min_rtt": None,
                "max_rtt": None,
                "rtt_history": [],  # Store last 100 RTT values
                "status": "idle"     # 'normal', 'warning', 'critical', 'idle'
            }

    def start(self) -> None:
        """Start monitoring in a separate daemon thread."""
        if self.is_running:
            logger.warning("Monitor for session %s is already running.", self.session_id)
            return

        self._stop_event.clear()
        self.is_running = True
        self.start_time = time.time()
        self._thread = threading.Thread(target=self._run_loop, name=f"PingMonitor-Session-{self.session_id}", daemon=True)
        self._thread.start()
        logger.info("Started PingMonitor for session %s with %d targets.", self.session_id, len(self.targets))

    def stop(self) -> None:
        """Signal monitor to stop immediately and wait for thread to join."""
        if not self.is_running:
            return
        logger.info("Stopping PingMonitor for session %s...", self.session_id)
        self._stop_event.set()
        self.is_running = False
        self.end_time = time.time()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("PingMonitor for session %s stopped.", self.session_id)

    def _run_loop(self) -> None:
        """Internal execution loop running on worker thread."""
        sequence = 0
        try:
            while not self._stop_event.is_set():
                loop_start = time.time()
                sequence += 1

                # Check duration limit (e.g. 11 hours = 39600s)
                if self.duration_sec and (loop_start - self.start_time) >= self.duration_sec:
                    logger.info("Session %s reached duration limit (%ds). Stopping.", self.session_id, self.duration_sec)
                    break

                # Check packet limit
                if self.packet_limit and sequence > self.packet_limit:
                    logger.info("Session %s reached packet limit (%d). Stopping.", self.session_id, self.packet_limit)
                    break

                # Ping each target in this iteration
                for item in self.targets:
                    if self._stop_event.is_set():
                        break

                    target = item["target"]
                    role = item.get("role", "target")
                    result = ping_single(target, timeout_sec=self.timeout_sec, target_role=role, sequence=sequence)

                    # Update internal statistics
                    self._update_stats(result)

                    # Fire callback (e.g., to write to DB)
                    if self.on_result_callback:
                        try:
                            self.on_result_callback(self.session_id, result)
                        except Exception as cb_err:
                            logger.error("Error in on_result_callback: %s", cb_err)

                # Sleep for remainder of interval
                elapsed = time.time() - loop_start
                sleep_time = max(0.01, self.interval_sec - elapsed)
                if self._stop_event.wait(timeout=sleep_time):
                    break

        except Exception as e:
            logger.error("Unexpected error in PingMonitor loop: %s", e, exc_info=True)
        finally:
            self.is_running = False
            self.end_time = time.time()

    def _update_stats(self, result: PingResult) -> None:
        """Update aggregate rolling metrics for a target."""
        tgt = result.target
        s = self.stats.get(tgt)
        if not s:
            return

        s["packets_sent"] += 1
        s["current_rtt"] = result.rtt_ms

        if result.success and result.rtt_ms is not None:
            s["packets_received"] += 1
            s["rtt_history"].append(result.rtt_ms)
            if len(s["rtt_history"]) > 100:
                s["rtt_history"].pop(0)

            # Update min/max/avg
            if s["min_rtt"] is None or result.rtt_ms < s["min_rtt"]:
                s["min_rtt"] = result.rtt_ms
            if s["max_rtt"] is None or result.rtt_ms > s["max_rtt"]:
                s["max_rtt"] = result.rtt_ms

            rtt_sum = sum(s["rtt_history"])
            s["avg_rtt"] = round(rtt_sum / len(s["rtt_history"]), 2)
        else:
            s["packets_lost"] += 1

        total = s["packets_sent"]
        lost = s["packets_lost"]
        s["loss_pct"] = round((lost / total) * 100.0, 2) if total > 0 else 0.0

        # Assess health status: Green (normal), Yellow (warning), Red (critical)
        if s["loss_pct"] >= 5.0 or (s["current_rtt"] is not None and s["current_rtt"] >= 150.0):
            s["status"] = "critical"
        elif s["loss_pct"] > 0.0 or (s["current_rtt"] is not None and s["current_rtt"] >= 75.0):
            s["status"] = "warning"
        else:
            s["status"] = "normal"

    def get_live_snapshot(self) -> Dict[str, Any]:
        """Return a structured real-time snapshot for frontend dashboard polling."""
        now = time.time()
        elapsed_sec = int(now - self.start_time) if self.start_time else 0
        hours = elapsed_sec // 3600
        minutes = (elapsed_sec % 3600) // 60
        seconds = elapsed_sec % 60
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        # Primary target summary (or combined)
        primary_target = self.targets[0]["target"] if self.targets else "None"
        primary_stats = self.stats.get(primary_target, {})

        return {
            "session_id": self.session_id,
            "is_running": self.is_running,
            "elapsed_sec": elapsed_sec,
            "duration_str": duration_str,
            "primary_target": primary_target,
            "primary_stats": primary_stats,
            "all_targets": list(self.stats.values()),
            "overall_status": primary_stats.get("status", "idle")
        }
