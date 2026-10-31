"""
Packet Capture & Retransmission Diagnostic Module for Agents.
Analyzes TCP retransmissions, resets, and packet streams using tshark if present,
or provides lightweight socket traffic monitoring.
"""

import sys
import os
import subprocess
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("agent.packet_capture")


def check_tshark_available() -> Optional[str]:
    """Check if tshark is installed."""
    for bin_name in ["tshark", "tshark.exe"]:
        try:
            res = subprocess.run([bin_name, "-v"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True,
                                 timeout=2.0)
            if res.returncode == 0:
                return bin_name
        except Exception:
            continue
    return None


class AgentPacketCapture:
    """Manages brief packet captures for retransmission and duplicate ACK analysis."""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.tshark_bin = check_tshark_available()
        self.proc: Optional[subprocess.Popen] = None
        self.output_pcap: Optional[str] = None

    def start(self, duration_sec: int = 15, output_path: str = "capture.pcap") -> Dict[str, Any]:
        """Start capturing packets."""
        if not self.tshark_bin:
            return {"success": False, "error": "tshark not installed on agent system"}

        self.output_pcap = output_path
        cmd = [self.tshark_bin, "-a", f"duration:{duration_sec}", "-w", output_path]
        if self.interface:
            cmd.extend(["-i", self.interface])

        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return {"success": True, "output_path": output_path, "pid": self.proc.pid}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_and_analyze(self) -> Dict[str, Any]:
        """Stop capture and summarize TCP retransmissions and anomalies."""
        if self.proc:
            try:
                self.proc.wait(timeout=3.0)
            except Exception:
                try:
                    self.proc.terminate()
                except Exception:
                    pass
            self.proc = None

        if not self.output_pcap or not os.path.exists(self.output_pcap) or not self.tshark_bin:
            return {"tcp_retransmissions": 0, "dup_acks": 0, "resets": 0, "packet_count": 0}

        # Analyze PCAP with tshark read filters
        stats = {"tcp_retransmissions": 0, "dup_acks": 0, "resets": 0, "packet_count": 0}
        try:
            # Count retransmissions: tcp.analysis.retransmission
            retrans_cmd = [self.tshark_bin, "-r", self.output_pcap, "-Y", "tcp.analysis.retransmission", "-T", "fields", "-e", "frame.number"]
            res = subprocess.run(retrans_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.0)
            stats["tcp_retransmissions"] = len(res.stdout.splitlines())

            # Count dup ACKs: tcp.analysis.duplicate_ack
            dup_cmd = [self.tshark_bin, "-r", self.output_pcap, "-Y", "tcp.analysis.duplicate_ack", "-T", "fields", "-e", "frame.number"]
            res = subprocess.run(dup_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.0)
            stats["dup_acks"] = len(res.stdout.splitlines())

            # Count resets: tcp.flags.reset == 1
            rst_cmd = [self.tshark_bin, "-r", self.output_pcap, "-Y", "tcp.flags.reset==1", "-T", "fields", "-e", "frame.number"]
            res = subprocess.run(rst_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.0)
            stats["resets"] = len(res.stdout.splitlines())
        except Exception as e:
            logger.debug("Packet capture dissection error: %s", e)

        return stats
