"""
Comprehensive Report Generator Module.
Generates CSV exports and publication-grade PDF investigation reports using fpdf2.
Clearly delineates empirical measurements, calculated statistical indicators,
and scientific engineering interpretations.
"""

import os
import io
import csv
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

from fpdf import FPDF
from database.db import (
    get_session, get_session_ping_measurements, get_ping_summary,
    get_recent_interface_stats, get_packet_captures,
    get_incident, get_comparative_tests, get_latest_analysis, DEFAULT_DB_PATH
)
from analysis.network_analysis import calculate_statistics

logger = logging.getLogger(__name__)


def generate_csv_report(session_id: int, db_path: str = DEFAULT_DB_PATH) -> str:
    """
    Generate standard CSV containing all raw ping measurements and sequence data.
    """
    measurements = get_session_ping_measurements(session_id, db_path=db_path)
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Sequence", "Timestamp", "Target", "Target_Role",
        "RTT_ms", "Success", "Timeout", "Error_Message"
    ])

    for m in measurements:
        writer.writerow([
            m.get("sequence_num"),
            m.get("timestamp"),
            m.get("target"),
            m.get("target_role"),
            m.get("rtt_ms") if m.get("rtt_ms") is not None else "",
            1 if m.get("success") else 0,
            1 if m.get("timeout") else 0,
            m.get("error_msg") or ""
        ])

    return output.getvalue()


class InvestigationPDF(FPDF):
    """Custom FPDF class with standardized headers, footers, and table helpers."""

    def header(self):
        # Top banner background
        self.set_fill_color(22, 32, 44)  # Dark slate navy
        self.rect(0, 0, 210, 24, "F")

        # Title text
        self.set_font("helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 5)
        self.cell(190, 8, "ELECTRICAL INTERFERENCE INVESTIGATION REPORT", align="L")

        # Sub-title
        self.set_font("helvetica", "", 8)
        self.set_text_color(180, 200, 220)
        self.set_xy(10, 13)
        self.cell(190, 6, "Physical-Layer Network Diagnostics & Root Cause Analysis", align="L")
        self.ln(14)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} of {{nb}}  |  Strictly Confidential - Network Engineering Telemetry", align="C")

    def section_heading(self, title: str):
        """Render a clean section heading."""
        self.set_font("helvetica", "B", 11)
        self.set_text_color(22, 45, 75)
        self.set_fill_color(235, 240, 248)
        self.cell(0, 7, f"  {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def label_value(self, label: str, value: str, width: float = 45):
        """Render a key-value pair."""
        self.set_font("helvetica", "B", 9)
        self.set_text_color(60, 60, 60)
        self.cell(width, 6, f"{label}:")
        self.set_font("helvetica", "", 9)
        self.set_text_color(20, 20, 20)
        self.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")


def generate_pdf_report(session_id: int, incident_id: Optional[int] = None,
                        output_path: Optional[str] = None,
                        db_path: str = DEFAULT_DB_PATH) -> str:
    """
    Generate a full technical PDF investigation report and return the file path.
    """
    session = get_session(session_id, db_path=db_path)
    if not session:
        raise ValueError(f"Session {session_id} not found.")

    measurements = get_session_ping_measurements(session_id, db_path=db_path)
    summary = get_ping_summary(session_id, db_path=db_path)
    if_stats = get_recent_interface_stats(session_id=session_id, limit=10, db_path=db_path)
    captures = get_packet_captures(session_id=session_id, db_path=db_path)
    latest_analysis = get_latest_analysis(session_id=session_id, incident_id=incident_id, db_path=db_path)

    incident = None
    tests = []
    if incident_id:
        incident = get_incident(incident_id, db_path=db_path)
        tests = get_comparative_tests(incident_id, db_path=db_path)

    # Initialize PDF
    pdf = InvestigationPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    # 1. Investigation Metadata Block
    pdf.section_heading("1. Investigation Metadata & Test Configuration")
    pdf.label_value("Session Name", session.get("name", "N/A"))
    pdf.label_value("Session ID", str(session_id))
    pdf.label_value("Target Host / IP", session.get("target", "N/A"))
    pdf.label_value("Monitoring Mode", session.get("mode", "single").replace("_", " ").title())
    pdf.label_value("Start Timestamp", session.get("start_time") or session.get("created_at", "N/A"))
    pdf.label_value("End Timestamp", session.get("end_time") or "Active / Incomplete")
    pdf.label_value("Ping Interval / Timeout", f"{session.get('interval_sec')} sec / {session.get('timeout_sec')} sec")
    if session.get("is_demo"):
        pdf.label_value("Data Origin", "BENCHMARK / DEMONSTRATION DATASET (Pre-recorded)")
    else:
        pdf.label_value("Data Origin", "REAL HARDWARE MEASUREMENTS (Live Subprocesses)")
    pdf.ln(3)

    # 2. Network Topology & Physical Environment
    pdf.section_heading("2. Physical Network Topology & Environment")
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(
        0, 5,
        "Network Topology: [Sender PC (192.168.10.10)] ---> [Ethernet Switch] ---> "
        "[Gateway Router (192.168.10.1)] ---> [Upstream / Internet]\n"
        "Associated Node: [Receiver PC (192.168.10.20)] connected to local switch."
    )
    pdf.ln(2)

    if incident:
        pdf.label_value("Site Location", incident.get("location", "Unspecified"))
        pdf.label_value("Installed Cable Type", incident.get("cable_type", "Unknown"))
        pdf.label_value("Estimated Cable Length", f"{incident.get('cable_length_m', 'N/A')} meters")
        pdf.label_value("Distance to Suspected Source", f"{incident.get('distance_to_source_m', 'N/A')} meters")
        pdf.label_value("Suspected Electrical Source", incident.get("electrical_source_type", "N/A").upper())
        pdf.label_value("Equipment Active During Test", "YES" if incident.get("equipment_operating") else "NO")
    else:
        pdf.label_value("Physical Environment", "Standard IT Room / Benchmarking Environment")
    pdf.ln(3)

    # 3. Empirical Ping Metrics Table
    pdf.section_heading("3. Measured Ping & Latency Metrics")
    rtts = [m["rtt_ms"] for m in measurements if m.get("rtt_ms") is not None]
    stats = calculate_statistics(rtts)

    # Table Header
    pdf.set_fill_color(240, 242, 245)
    pdf.set_font("helvetica", "B", 8)
    pdf.cell(32, 6, "Packets Sent", 1, align="C", fill=True)
    pdf.cell(32, 6, "Packets Recv", 1, align="C", fill=True)
    pdf.cell(32, 6, "Packet Loss %", 1, align="C", fill=True)
    pdf.cell(32, 6, "Average RTT", 1, align="C", fill=True)
    pdf.cell(32, 6, "Min / Max RTT", 1, align="C", fill=True)
    pdf.cell(30, 6, "Jitter (StdDev)", 1, align="C", fill=True, new_x="LMARGIN", new_y="NEXT")

    # Table Row
    pdf.set_font("helvetica", "", 8)
    pdf.cell(32, 6, str(summary.get("total_packets", 0)), 1, align="C")
    pdf.cell(32, 6, str(summary.get("successful_packets", 0)), 1, align="C")
    loss_val = summary.get("loss_pct", 0.0)
    pdf.cell(32, 6, f"{loss_val:.2f}%", 1, align="C")
    pdf.cell(32, 6, f"{summary.get('avg_rtt', 0.0)} ms", 1, align="C")
    pdf.cell(32, 6, f"{summary.get('min_rtt', 0.0)} / {summary.get('max_rtt', 0.0)} ms", 1, align="C")
    pdf.cell(30, 6, f"{stats.get('jitter', 0.0)} ms", 1, align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # 4. Physical Network Interface & CRC Counters
    pdf.section_heading("4. Physical Interface Error & Hardware CRC/FCS Counters")
    if if_stats:
        latest_if = if_stats[-1]
        pdf.label_value("Interface Name", latest_if.get("interface_name", "N/A"))
        pdf.label_value("Link State & Speed", f"{'UP' if latest_if.get('is_up') else 'DOWN'} @ {latest_if.get('link_speed_mbps')} Mbps")
        pdf.label_value("Observed Rx Errors (Delta)", f"{latest_if.get('rx_errors', 0)} ({latest_if.get('rx_errors_delta', 0)} new)")
        pdf.label_value("Observed Tx Errors (Delta)", f"{latest_if.get('tx_errors', 0)} ({latest_if.get('tx_errors_delta', 0)} new)")
        pdf.label_value("Observed Dropped Packets", f"Rx: {latest_if.get('rx_drops', 0)}, Tx: {latest_if.get('tx_drops', 0)}")
        pdf.label_value("Hardware CRC/FCS Counter Delta", str(latest_if.get("crc_fcs_delta", 0)))
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.cell(0, 6, "No interface statistics were recorded for this session.", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", "I", 7.5)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(
        0, 4,
        "Scientific Note: Modern OS network drivers and standard NICs discard corrupted frames at the "
        "physical MAC layer before reporting to OS counters. To verify frame check sequence (FCS) corruptions, "
        "enterprise managed switches with SNMP (RFC 1643) or specialized test equipment must be queried."
    )
    pdf.ln(3)

    # 5. Comparative Isolation Tests (Test A, B, C, D)
    if tests:
        pdf.section_heading("5. Comparative Isolation Testing Matrix")
        pdf.set_fill_color(240, 242, 245)
        pdf.set_font("helvetica", "B", 8)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(15, 6, "Test", 1, align="C", fill=True)
        pdf.cell(50, 6, "Condition Description", 1, align="L", fill=True)
        pdf.cell(25, 6, "Duration", 1, align="C", fill=True)
        pdf.cell(25, 6, "Avg RTT", 1, align="C", fill=True)
        pdf.cell(25, 6, "Packet Loss", 1, align="C", fill=True)
        pdf.cell(50, 6, "Observations", 1, align="L", fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("helvetica", "", 7.5)
        for t in tests:
            pdf.cell(15, 6, f"Test {t.get('test_code')}", 1, align="C")
            pdf.cell(50, 6, str(t.get('title', ''))[:30], 1, align="L")
            pdf.cell(25, 6, f"{t.get('duration_sec')}s", 1, align="C")
            pdf.cell(25, 6, f"{t.get('avg_rtt', 0.0)} ms", 1, align="C")
            pdf.cell(25, 6, f"{t.get('packet_loss_pct', 0.0)}%", 1, align="C")
            pdf.cell(50, 6, str(t.get('observations', ''))[:35], 1, align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # 6. Wireshark / TShark Deep Packet Dissection
    if captures:
        pdf.section_heading("6. Wireshark / TShark Packet Dissection Summary")
        cap = captures[0]
        pdf.label_value("Capture File", cap.get("filename", "N/A"))
        pdf.label_value("Captured Packets", str(cap.get("packet_count", 0)))
        pdf.label_value("TCP Retransmissions", str(cap.get("tcp_retransmissions", 0)))
        pdf.label_value("TCP Duplicate ACKs", str(cap.get("dup_acks", 0)))
        pdf.label_value("DNS Query Failures", str(cap.get("dns_failures", 0)))
        pdf.label_value("TCP Connection Resets (RST)", str(cap.get("tcp_resets", 0)))
        if cap.get("analysis_notes"):
            pdf.set_font("helvetica", "I", 8)
            pdf.multi_cell(0, 4.5, f"Dissection Notes: {cap.get('analysis_notes')}")
        pdf.ln(3)

    # 7. Scientific Diagnosis & Root-Cause Classification
    pdf.section_heading("7. Scientific Correlation & Diagnostic Classification")
    if latest_analysis:
        cat_label = latest_analysis.get("category", "insufficient_evidence").replace("_", " ").upper()
        confidence = latest_analysis.get("confidence_score", 0.0)

        pdf.label_value("Diagnostic Category", cat_label)
        pdf.label_value("Evidence Quality & Confidence", f"{confidence:.1f}%")
        pdf.ln(1)

        findings = latest_analysis.get("findings", [])
        if findings:
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(40, 40, 40)
            pdf.cell(0, 5, "Correlated Key Evidence:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 8)
            for f in findings:
                pdf.multi_cell(0, 5, f"  - {f}", new_x="LMARGIN", new_y="NEXT")

        recommendations = latest_analysis.get("recommendations", [])
        if recommendations:
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 8.5)
            pdf.cell(0, 5, "Recommended Next Steps & Technical Remediation:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 8)
            for r in recommendations:
                pdf.multi_cell(0, 5, f"  * {r}", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("helvetica", "I", 8.5)
        pdf.cell(0, 6, "Analysis correlation engine has not been run on this session yet.", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)

    # 8. Standards & Electrical Safety Disclaimer
    pdf.section_heading("8. Standards Compliance & Safety Disclaimers")
    pdf.set_font("helvetica", "", 7.5)
    pdf.set_text_color(110, 30, 30)
    pdf.multi_cell(
        0, 4,
        "ELECTRICAL SAFETY NOTICE: Personnel investigating physical network issues must NEVER open electrical "
        "distribution cabinets, touch exposed wiring conductors, or defeat electrical safety interlocks. All electrical "
        "inspections must be conducted by certified electricians.\n"
        "STANDARDS COMPLIANCE: Ethernet cabling runs should comply with ANSI/TIA-568.0-D and ISO/IEC 11801 standards. "
        "Maintain a minimum clearance of 200 mm (8 inches) between unshielded network cables and fluorescent lighting ballasts, "
        "high-voltage AC power conduits, or variable frequency drives (VFDs)."
    )

    # Save to file
    if not output_path:
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "generated_reports")
        os.makedirs(reports_dir, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(reports_dir, f"report_session_{session_id}_{timestamp_str}.pdf")

    pdf.output(output_path)
    logger.info("Generated PDF investigation report: %s", output_path)
    return output_path
