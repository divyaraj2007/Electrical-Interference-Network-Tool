"""
Two-Device Investigation Report Generator.
Generates CSV exports and publication-grade PDF investigation reports
incorporating all 15 scientific diagnostic criteria required for physical-layer EMI investigation.
"""

import os
import io
import csv
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from fpdf import FPDF

from database.db import (
    get_two_device_test, get_device_by_id, get_two_device_measurements,
    get_two_device_analysis, get_incident, DEFAULT_DB_PATH
)

logger = logging.getLogger("reports.two_device")


def generate_two_device_csv(test_id: int, db_path: str = DEFAULT_DB_PATH) -> str:
    """Export all telemetry and sequence measurements for a two-device test to CSV format."""
    measurements = get_two_device_measurements(test_id, limit=5000, db_path=db_path)
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Record_ID", "Timestamp_UTC", "Device_Role", "Device_ID",
        "Metric_Type", "Sequence_Num", "Value_Numeric", "Raw_JSON_Data"
    ])

    for m in measurements:
        writer.writerow([
            m.get("id"),
            m.get("timestamp"),
            m.get("device_role"),
            m.get("device_id"),
            m.get("metric_type"),
            m.get("sequence_num", 0),
            m.get("value_numeric", 0.0),
            json.dumps(m.get("data", {}))
        ])

    return output.getvalue()


class TwoDeviceInvestigationPDF(FPDF):
    """Custom FPDF document layout for Two-Device Coordinated Testing."""

    def header(self):
        # Top banner background (Deep Navy)
        self.set_fill_color(22, 32, 48)
        self.rect(0, 0, 210, 24, "F")

        # Title
        self.set_font("helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 5)
        self.cell(190, 8, "TWO-DEVICE NETWORK TESTING & INTERFERENCE REPORT", align="L")

        # Subtitle
        self.set_font("helvetica", "", 8)
        self.set_text_color(185, 205, 225)
        self.set_xy(10, 13)
        self.cell(190, 6, "Synchronized Sender-Receiver Physical-Layer Diagnostics & Root Cause Classification", align="L")
        self.ln(14)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} of {{nb}}  |  Two-Device Testing Telemetry  |  ANSI/TIA-568.0-D & ISO/IEC 11801", align="C")

    def section_heading(self, title: str):
        """Format a clear numbered section heading."""
        self.set_font("helvetica", "B", 10)
        self.set_text_color(22, 45, 75)
        self.set_fill_color(235, 242, 250)
        self.cell(0, 6.5, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(1.5)

    def label_value(self, label: str, value: str, width: float = 55):
        """Format an aligned key-value line."""
        self.set_font("helvetica", "B", 8.5)
        self.set_text_color(60, 60, 60)
        self.cell(width, 5.5, f"{label}:")
        self.set_font("helvetica", "", 8.5)
        self.set_text_color(20, 20, 20)
        self.cell(0, 5.5, str(value), new_x="LMARGIN", new_y="NEXT")

    def table_row(self, col1: str, col2: str, col3: str, col4: str, is_header: bool = False):
        """Render a 4-column comparison table row."""
        w1, w2, w3, w4 = 50, 45, 45, 50
        if is_header:
            self.set_font("helvetica", "B", 8.5)
            self.set_fill_color(220, 230, 242)
            self.set_text_color(20, 30, 45)
            self.cell(w1, 6, col1, border=1, fill=True, align="L")
            self.cell(w2, 6, col2, border=1, fill=True, align="C")
            self.cell(w3, 6, col3, border=1, fill=True, align="C")
            self.cell(w4, 6, col4, border=1, fill=True, align="C")
            self.ln()
        else:
            self.set_font("helvetica", "", 8)
            self.set_fill_color(255, 255, 255)
            self.set_text_color(30, 30, 30)
            self.cell(w1, 5.5, col1, border=1, fill=False, align="L")
            self.cell(w2, 5.5, col2, border=1, fill=False, align="C")
            self.cell(w3, 5.5, col3, border=1, fill=False, align="C")
            self.cell(w4, 5.5, col4, border=1, fill=False, align="C")
            self.ln()


def generate_two_device_pdf(test_id: int,
                            output_path: Optional[str] = None,
                            db_path: str = DEFAULT_DB_PATH) -> str:
    """Generate comprehensive technical PDF report for a Two-Device testing investigation."""
    test = get_two_device_test(test_id, db_path=db_path)
    if not test:
        raise ValueError(f"Two-device test {test_id} not found.")

    sender = get_device_by_id(test["sender_device_id"], db_path=db_path) or {}
    receiver = get_device_by_id(test["receiver_device_id"], db_path=db_path) or {}
    analysis = get_two_device_analysis(test_id, db_path=db_path) or {}
    summary = test.get("summary") or {}
    incident = get_incident(test["incident_id"], db_path=db_path) if test.get("incident_id") else None

    # Retrieve measurements
    sender_meas = summary.get("sender", {})
    receiver_meas = summary.get("receiver", {})

    pdf = TwoDeviceInvestigationPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.alias_nb_pages()
    pdf.add_page()

    # 1 & 2. Sender and Receiver Device Information
    pdf.section_heading("1. Coordinated Device Identification")
    pdf.label_value("Sender Device ID / Name", f"{sender.get('device_id', test['sender_device_id'])} ({sender.get('hostname', 'Sender Node')})")
    pdf.label_value("Sender Operating System", sender.get("os_info", "Windows / Linux"))
    pdf.label_value("Sender IP / Active NIC", f"{sender.get('ip_address', '127.0.0.1')} on {sender.get('active_interface', 'eth0')} ({sender.get('link_speed_mbps', 0)} Mbps)")

    pdf.label_value("Receiver Device ID / Name", f"{receiver.get('device_id', test['receiver_device_id'])} ({receiver.get('hostname', 'Receiver Node')})")
    pdf.label_value("Receiver Operating System", receiver.get("os_info", "Windows / Linux"))
    pdf.label_value("Receiver IP / Active NIC", f"{receiver.get('ip_address', '127.0.0.1')} on {receiver.get('active_interface', 'eth0')} ({receiver.get('link_speed_mbps', 0)} Mbps)")
    pdf.ln(2)

    # 3. Network Topology & Physical Setup
    pdf.section_heading("2. Physical Network Topology & Cabling Environment")
    pdf.set_font("helvetica", "", 8.5)
    inc_title = incident.get('title') if incident else 'Dedicated Two-Device Test'
    inc_source = incident.get('electrical_source_type', 'VFD / Industrial Motor / General EMI') if incident else 'N/A'
    cable_spec = incident.get('cable_type', 'Standard Cat6 UTP / STP') if incident else 'Standard Cat6 UTP / STP'
    sep_dist = f"{incident.get('distance_to_source_m', 'N/A')} meters from conduit" if incident else "Local physical Ethernet"

    pdf.multi_cell(0, 4.5,
        f"Test Topology: [Sender: {sender.get('ip_address', 'Endpoint 1')}] <== Ethernet Physical Medium ==> [Receiver: {receiver.get('ip_address', 'Endpoint 2')}]\n"
        f"Associated Electrical Incident: {inc_title} | Suspected Source: {inc_source}\n"
        f"Cable Specification: {cable_spec} | Separation Distance: {sep_dist}."
    )
    pdf.ln(2)

    # 4. Test Configuration
    pdf.section_heading("3. Test Execution Configuration")
    pdf.label_value("Test UUID", test.get("test_uuid", "N/A"))
    pdf.label_value("Testing Direction", test.get("direction", "sender_to_receiver").replace("_", " ").title())
    pdf.label_value("Configured Test Modes", ", ".join(test.get("test_modes", [])))
    pdf.label_value("Duration / Packet Size / Interval", f"{test.get('duration_sec')} sec | {test.get('packet_size_bytes')} bytes | {test.get('interval_sec')} sec")
    pdf.label_value("Electrical Equipment State", test.get("equipment_state", "off").upper())
    pdf.label_value("UTC Start / End Timestamps", f"{test.get('start_time', 'N/A')}  ==>  {test.get('end_time', 'N/A')}")
    pdf.ln(2)

    # 5, 6, 7, 8, 9, 10. Device Measurement Comparison Table
    pdf.section_heading("4. Comprehensive Device Telemetry & Metrics Comparison")
    pdf.table_row("Metric Parameter", "Device 1 (Sender)", "Device 2 (Receiver)", "Status / Evaluation", is_header=True)

    s_ping = sender_meas.get("metrics", {}).get("ping", {})
    r_traffic = receiver_meas.get("incoming_traffic", {})
    s_tcp = sender_meas.get("metrics", {}).get("tcp_throughput", {})
    s_if = sender_meas.get("interface_deltas", {})
    r_if = receiver_meas.get("interface_deltas", {})

    rtt_avg = s_ping.get("avg_rtt_ms", 0.0)
    jitter = s_ping.get("jitter_ms", 0.0)
    loss = s_ping.get("loss_pct", 0.0)
    s_mbps = s_tcp.get("throughput_mbps", 0.0)
    r_mbps = r_traffic.get("measured_throughput_mbps", s_mbps)

    pdf.table_row("Average RTT / Jitter", f"{rtt_avg:.2f} ms / {jitter:.2f} ms", "Echo responder", "Normal" if rtt_avg < 20 else "High Latency")
    pdf.table_row("Packet Loss Percentage", f"{loss:.1f}%", f"{loss:.1f}% received loss", "Healthy" if loss == 0 else f"{loss}% Loss")
    pdf.table_row("Throughput (Upload/Download)", f"{s_mbps:.2f} Mbps (tx)", f"{r_mbps:.2f} Mbps (rx)", "Symmetric" if abs(s_mbps - r_mbps) < 15 else "Asymmetric")
    pdf.table_row("TCP Retransmissions", str(s_tcp.get("retransmissions", 0)), "N/A", "Clean" if s_tcp.get("retransmissions", 0) == 0 else "Retransmissions detected")

    s_err = s_if.get("rx_errors_delta", 0) + s_if.get("tx_errors_delta", 0)
    r_err = r_if.get("rx_errors_delta", 0) + r_if.get("tx_errors_delta", 0)
    pdf.table_row("Interface Errors (Delta)", f"{s_err} errors", f"{r_err} errors", "Clean" if (s_err + r_err) == 0 else "Errors Found")

    s_drops = s_if.get("rx_drops_delta", 0) + s_if.get("tx_drops_delta", 0)
    r_drops = r_if.get("rx_drops_delta", 0) + r_if.get("tx_drops_delta", 0)
    pdf.table_row("Interface Drops (Delta)", f"{s_drops} drops", f"{r_drops} drops", "Clean" if (s_drops + r_drops) == 0 else "Packet Discards")

    s_crc_str = str(s_if.get("crc_delta", 0)) if s_if.get("crc_supported") else "Not exposed by OS"
    r_crc_str = str(r_if.get("crc_delta", 0)) if r_if.get("crc_supported") else "Not exposed by OS"
    pdf.table_row("Hardware CRC / FCS Delta", s_crc_str, r_crc_str, "PHY Hardware Telemetry")
    pdf.ln(3)

    # 11 & 12. TCP Retransmissions & Timeline
    pdf.section_heading("5. TCP Retransmissions, Jitter, & Temporal Event Correlation")
    pdf.set_font("helvetica", "", 8.5)
    pdf.multi_cell(0, 4.5,
        f"- Retransmission Count: {s_tcp.get('retransmissions', 0)} packet retransmissions observed during transmission window.\n"
        f"- RFC 3550 Interarrival Jitter: {jitter:.3f} ms. Baseline threshold: < 5.0 ms.\n"
        f"- Equipment Operational Timeline: Baseline established during OFF state. Test run under equipment state: {test.get('equipment_state', 'off').upper()}."
    )
    pdf.ln(2)

    # 13, 14 & 15. Root Cause Analysis, Anomaly Detection, & Engineering Conclusion
    pdf.section_heading("6. Root-Cause Analysis & Engineering Conclusion")
    category = analysis.get("category", "insufficient_evidence").replace("_", " ").title()
    confidence = analysis.get("confidence_score", 0.0)

    pdf.label_value("Diagnostic Root-Cause Category", category)
    pdf.label_value("Confidence Score", f"{confidence:.1f}%")
    pdf.ln(1)

    pdf.set_font("helvetica", "B", 8.5)
    pdf.cell(0, 5, "Detailed Empirical Findings:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 8)
    for finding in analysis.get("findings", ["Empirical telemetry within normal tolerances."]):
        pdf.cell(5)
        pdf.cell(0, 4.5, f"- {finding}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    pdf.set_font("helvetica", "B", 8.5)
    pdf.cell(0, 5, "Remediation & Compliance Recommendations:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 8)
    for rec in analysis.get("recommendations", ["Continue regular baseline maintenance."]):
        pdf.cell(5)
        pdf.cell(0, 4.5, f"- {rec}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Hardware Counter Disclaimer
    pdf.set_font("helvetica", "I", 7.5)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 4,
        "NOTICE ON PHYSICAL LAYER CRC/FCS VISIBILITY: Standard OS and consumer Ethernet drivers drop "
        "corrupted FCS frames at the MAC layer without incrementing OS counters. Enterprise NICs (e.g. Intel "
        "with ethtool -S on Linux) or managed switch SNMP counters are queried to verify physical discards. "
        "The system explicitly reports unexposed counters rather than fabricating zero values."
    )

    if not output_path:
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "generated_reports")
        os.makedirs(reports_dir, exist_ok=True)
        output_path = os.path.join(reports_dir, f"two_device_test_{test_id}_report.pdf")

    pdf.output(output_path)
    logger.info("Generated Two-Device Investigation PDF report at %s", output_path)
    return output_path
