"""
Wireshark & TShark Integration Module for Network Investigation.
Manages live captures, background dumpcap/tshark subprocesses, protocol breakdowns,
TCP retransmissions, duplicate ACKs, DNS errors, and offline PCAP/PCAPNG import.
Includes a pure-Python fallback PCAP parser for environments without TShark installed.
"""

import os
import sys
import shutil
import struct
import subprocess
import threading
import time
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Scientific documentation note
TSHARK_LIMITATION_NOTICE = (
    "PACKET CAPTURE LIMITATION: Standard packet captures (via Npcap, libpcap, or Wireshark) "
    "CANNOT reveal physical Ethernet CRC/FCS error frames. Ethernet controllers discard frames "
    "with invalid Frame Check Sequences in hardware before delivering packets to the host OS. "
    "Consequently, packet captures only show secondary symptoms (such as TCP retransmissions "
    "or connection timeouts) rather than the physical corrupted frames themselves."
)


def find_tshark_binary() -> Optional[str]:
    """Locate tshark binary across Windows and Linux standard install paths."""
    # Check PATH first
    path_bin = shutil.which("tshark")
    if path_bin and os.path.exists(path_bin):
        return path_bin

    # Windows common locations
    win_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    for p in win_paths:
        if os.path.exists(p):
            return p

    # Linux common locations
    linux_paths = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
    for p in linux_paths:
        if os.path.exists(p):
            return p

    return None


def get_tshark_interfaces() -> List[Dict[str, Any]]:
    """List interfaces available for packet capture via TShark or system fallback."""
    tshark_path = find_tshark_binary()
    interfaces = []

    if tshark_path:
        try:
            proc = subprocess.run([tshark_path, "-D"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.0)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    # Format: 1. \Device\NPF_{...} (Wi-Fi)
                    parts = line.strip().split(". ", 1)
                    if len(parts) == 2:
                        idx = parts[0].strip()
                        desc = parts[1].strip()
                        interfaces.append({
                            "index": idx,
                            "identifier": idx,
                            "description": desc,
                            "source": "tshark"
                        })
                if interfaces:
                    return interfaces
        except Exception as e:
            logger.debug("tshark -D failed: %s", e)

    # Fallback to psutil interfaces
    import psutil
    for name, stats in psutil.net_if_stats().items():
        interfaces.append({
            "index": name,
            "identifier": name,
            "description": f"{name} ({'UP' if stats.isup else 'DOWN'}, {stats.speed} Mbps)",
            "source": "system"
        })

    return interfaces


def parse_pcap_file_fallback(filepath: str) -> Dict[str, Any]:
    """
    Pure Python lightweight parser for standard libpcap files (.pcap).
    Parses global header, packet timestamps, sizes, IPv4 protocols, and TCP flags
    without requiring Wireshark, TShark, or external C-libraries.
    """
    if not os.path.exists(filepath):
        return {"error": "File not found"}

    summary = {
        "packet_count": 0,
        "duration_sec": 0.0,
        "file_size_bytes": os.path.getsize(filepath),
        "tcp_retransmissions": 0,
        "dup_acks": 0,
        "dns_failures": 0,
        "tcp_resets": 0,
        "protocol_summary": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
        "first_timestamp": None,
        "last_timestamp": None
    }

    try:
        with open(filepath, "rb") as f:
            # 24-byte pcap global header
            global_header = f.read(24)
            if len(global_header) < 24:
                return summary

            magic = struct.unpack("!I", global_header[0:4])[0]
            # Standard PCAP magic numbers: 0xa1b2c3d4 (same endian) or 0xd4c3b2a1 (swapped)
            endian = "!"
            if magic == 0xa1b2c3d4:
                endian = ">"
            elif magic == 0xd4c3b2a1:
                endian = "<"
            elif magic == 0x0a0d0d0a:
                # PCAPNG file format
                summary["protocol_summary"] = {"PCAPNG": "Native dissection requires TShark"}
                return summary
            else:
                # Unknown header
                return summary

            first_ts = None
            last_ts = None

            while True:
                # 16-byte packet header: ts_sec, ts_usec, incl_len, orig_len
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                summary["packet_count"] += 1
                pkt_time = ts_sec + (ts_usec / 1000000.0)
                if first_ts is None:
                    first_ts = pkt_time
                last_ts = pkt_time

                # Parse Ethernet frame (14 bytes header: dst(6), src(6), ethertype(2))
                if len(pkt_data) > 14:
                    ethertype = struct.unpack("!H", pkt_data[12:14])[0]
                    if ethertype == 0x0800 and len(pkt_data) > 34:  # IPv4
                        ip_proto = pkt_data[23]
                        if ip_proto == 6:  # TCP
                            summary["protocol_summary"]["TCP"] = summary["protocol_summary"].get("TCP", 0) + 1
                            # Check TCP flags at offset 14 + 20 + 13 = 47
                            if len(pkt_data) >= 48:
                                tcp_flags = pkt_data[47]
                                if tcp_flags & 0x04:  # RST flag
                                    summary["tcp_resets"] += 1
                        elif ip_proto == 17:  # UDP
                            summary["protocol_summary"]["UDP"] = summary["protocol_summary"].get("UDP", 0) + 1
                        elif ip_proto == 1:  # ICMP
                            summary["protocol_summary"]["ICMP"] = summary["protocol_summary"].get("ICMP", 0) + 1
                        else:
                            summary["protocol_summary"]["Other"] = summary["protocol_summary"].get("Other", 0) + 1
                    else:
                        summary["protocol_summary"]["Other"] = summary["protocol_summary"].get("Other", 0) + 1

            if first_ts and last_ts:
                summary["duration_sec"] = round(max(0.0, last_ts - first_ts), 2)

    except Exception as e:
        logger.error("Error in fallback PCAP parser: %s", e)

    return summary


def analyze_pcap_with_tshark(tshark_bin: str, filepath: str) -> Dict[str, Any]:
    """
    Perform deep packet dissection using TShark command-line queries.
    Identifies TCP retransmissions, duplicate ACKs, DNS errors, and protocol tree.
    """
    summary = {
        "packet_count": 0,
        "duration_sec": 0.0,
        "file_size_bytes": os.path.getsize(filepath) if os.path.exists(filepath) else 0,
        "tcp_retransmissions": 0,
        "dup_acks": 0,
        "dns_failures": 0,
        "tcp_resets": 0,
        "protocol_summary": {},
        "analysis_notes": ""
    }

    try:
        # 1. Total packet count and basic protocol hierarchy
        proc_phs = subprocess.run(
            [tshark_bin, "-r", filepath, "-q", "-z", "io,phs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15.0
        )
        if proc_phs.returncode == 0:
            for line in proc_phs.stdout.splitlines():
                if "frames:" in line:
                    parts = line.split("frames:")
                    try:
                        summary["packet_count"] = max(summary["packet_count"], int(parts[1].split()[0]))
                    except (IndexError, ValueError):
                        pass
                for proto in ["tcp", "udp", "icmp", "dns", "http", "tls", "arp"]:
                    if f" {proto} " in line.lower():
                        summary["protocol_summary"][proto.upper()] = summary["protocol_summary"].get(proto.upper(), 0) + 1

        # 2. Query TCP retransmissions
        proc_retx = subprocess.run(
            [tshark_bin, "-r", filepath, "-Y", "tcp.analysis.retransmission", "-T", "fields", "-e", "frame.number"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0
        )
        if proc_retx.returncode == 0:
            lines = [l for l in proc_retx.stdout.splitlines() if l.strip()]
            summary["tcp_retransmissions"] = len(lines)

        # 3. Query duplicate ACKs
        proc_dupack = subprocess.run(
            [tshark_bin, "-r", filepath, "-Y", "tcp.analysis.duplicate_ack", "-T", "fields", "-e", "frame.number"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0
        )
        if proc_dupack.returncode == 0:
            lines = [l for l in proc_dupack.stdout.splitlines() if l.strip()]
            summary["dup_acks"] = len(lines)

        # 4. Query DNS failures (RCODE != 0)
        proc_dns = subprocess.run(
            [tshark_bin, "-r", filepath, "-Y", "dns.flags.rcode != 0", "-T", "fields", "-e", "frame.number"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0
        )
        if proc_dns.returncode == 0:
            lines = [l for l in proc_dns.stdout.splitlines() if l.strip()]
            summary["dns_failures"] = len(lines)

        # 5. Query TCP Resets (flags.reset == 1)
        proc_rst = subprocess.run(
            [tshark_bin, "-r", filepath, "-Y", "tcp.flags.reset == 1", "-T", "fields", "-e", "frame.number"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10.0
        )
        if proc_rst.returncode == 0:
            lines = [l for l in proc_rst.stdout.splitlines() if l.strip()]
            summary["tcp_resets"] = len(lines)

        # Add interpretation notes
        notes = []
        if summary["tcp_retransmissions"] > 0:
            notes.append(f"{summary['tcp_retransmissions']} TCP retransmissions detected (indicates packet loss or buffer drops).")
        if summary["dup_acks"] > 0:
            notes.append(f"{summary['dup_acks']} duplicate ACKs observed (indicates out-of-order delivery or packet drop).")
        if summary["dns_failures"] > 0:
            notes.append(f"{summary['dns_failures']} DNS lookup failures observed.")
        if summary["tcp_resets"] > 0:
            notes.append(f"{summary['tcp_resets']} TCP reset (RST) packets observed.")
        if not notes:
            notes.append("No abnormal TCP retransmissions or protocol anomalies observed in capture.")

        summary["analysis_notes"] = " ".join(notes)

    except Exception as e:
        logger.error("TShark analysis error: %s", e)
        summary["analysis_notes"] = f"TShark analysis encountered an error: {e}"

    return summary


class PacketCaptureManager:
    """
    Coordinates packet capture subprocesses and file persistence.
    """

    def __init__(self, capture_dir: Optional[str] = None):
        if capture_dir is None:
            capture_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "captures")
        self.capture_dir = capture_dir
        os.makedirs(self.capture_dir, exist_ok=True)

        self.current_process: Optional[subprocess.Popen] = None
        self.active_filepath: Optional[str] = None
        self.active_filename: Optional[str] = None
        self.start_time: Optional[float] = None
        self.interface_name: Optional[str] = None
        self.is_capturing = False

    def is_tshark_available(self) -> bool:
        """Check if TShark is installed and accessible."""
        return find_tshark_binary() is not None

    def start_capture(self, interface_id: str, duration_sec: int = 60,
                      packet_limit: int = 5000) -> Dict[str, Any]:
        """
        Start a packet capture on an authorized interface.
        If TShark is available, runs tshark in a background subprocess.
        """
        if self.is_capturing:
            return {"success": False, "error": "Capture already in progress."}

        tshark_bin = find_tshark_binary()
        if not tshark_bin:
            return {
                "success": False,
                "error": "TShark/Wireshark executable not found on system. Install Wireshark or use offline PCAP upload.",
                "tshark_installed": False
            }

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.active_filename = f"capture_{timestamp_str}.pcapng"
        self.active_filepath = os.path.join(self.capture_dir, self.active_filename)
        self.interface_name = interface_id
        self.start_time = time.time()

        # Build safe tshark command without shell
        cmd = [
            tshark_bin,
            "-i", str(interface_id),
            "-w", self.active_filepath,
            "-a", f"duration:{duration_sec}",
            "-c", str(packet_limit)
        ]

        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            self.is_capturing = True
            logger.info("Started TShark capture on interface %s -> %s", interface_id, self.active_filepath)
            return {
                "success": True,
                "filename": self.active_filename,
                "filepath": self.active_filepath,
                "interface": interface_id,
                "duration_limit": duration_sec
            }
        except Exception as e:
            self.is_capturing = False
            return {"success": False, "error": str(e)}

    def stop_capture(self) -> Dict[str, Any]:
        """Stop running capture process gracefully and analyze the resulting capture file."""
        if not self.is_capturing or not self.current_process:
            return {"success": False, "error": "No capture actively running."}

        try:
            self.current_process.terminate()
            try:
                self.current_process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.current_process.kill()
        except Exception as e:
            logger.warning("Error terminating capture process: %s", e)

        self.is_capturing = False
        duration = round(time.time() - self.start_time, 2) if self.start_time else 0.0

        # Run analysis on the generated file
        result = self.analyze_file(self.active_filepath)
        result["duration_sec"] = duration
        result["filename"] = self.active_filename
        result["filepath"] = self.active_filepath
        result["interface_name"] = self.interface_name
        return result

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """Analyze a PCAP or PCAPNG file using TShark or the Python fallback."""
        if not os.path.exists(filepath):
            return {"error": f"Capture file {filepath} not found."}

        tshark_bin = find_tshark_binary()
        if tshark_bin:
            analysis = analyze_pcap_with_tshark(tshark_bin, filepath)
        else:
            analysis = parse_pcap_file_fallback(filepath)
            analysis["analysis_notes"] = (
                "Parsed via built-in Python PCAP engine. "
                "Install TShark for TCP retransmission and deep dissections."
            )

        analysis["filename"] = os.path.basename(filepath)
        analysis["filepath"] = filepath
        analysis["disclaimer"] = TSHARK_LIMITATION_NOTICE
        return analysis
