"""
Electrical Interference Investigation Tool for Computer Networks
Main Flask Application Server & REST API Endpoints.
"""

import os
import sys
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, Any

from flask import (
    Flask, render_template, request, jsonify, send_file, redirect, url_for, Response
)

# Internal module imports
from database.db import (
    init_db, create_session, start_session, end_session, get_session,
    get_active_session, get_all_sessions, record_ping_measurement,
    get_session_ping_measurements, get_recent_ping_measurements,
    get_ping_summary, record_interface_stats, get_recent_interface_stats,
    create_incident, get_incidents, get_incident,
    record_comparative_test, get_comparative_tests,
    record_packet_capture, get_packet_captures,
    record_analysis_result, get_latest_analysis,
    save_snmp_config, get_snmp_configs, DEFAULT_DB_PATH
)
from monitoring.ping_monitor import PingMonitor, validate_target, ping_single
from monitoring.interface_stats import (
    InterfaceStatsMonitor, get_all_interfaces_summary, PHYSICAL_LAYER_DISCLAIMER
)
from monitoring.snmp_monitor import SnmpSwitchMonitor
from monitoring.packet_capture import (
    PacketCaptureManager, find_tshark_binary, get_tshark_interfaces, TSHARK_LIMITATION_NOTICE
)
from analysis.network_analysis import calculate_statistics, detect_latency_spikes, compare_periods
from analysis.correlation import InvestigationCorrelationEngine
from reports.report_generator import generate_csv_report, generate_pdf_report
from sample_data.seed_demo_data import seed_all_demo_data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("emi_tool")

# Initialize Flask App
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload for PCAPs

CAPTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_reports")
os.makedirs(CAPTURES_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Global active monitors & managers
active_ping_monitor: Optional[PingMonitor] = None
active_interface_monitor: Optional[InterfaceStatsMonitor] = None
capture_manager = PacketCaptureManager(capture_dir=CAPTURES_DIR)
monitor_lock = threading.Lock()


def db_ping_callback(session_id: int, result):
    """Callback fired by PingMonitor to persist measurements directly into SQLite."""
    try:
        record_ping_measurement(
            session_id=session_id,
            target=result.target,
            sequence_num=result.sequence,
            rtt_ms=result.rtt_ms,
            success=result.success,
            timeout=result.timeout,
            error_msg=result.error_msg,
            target_role=result.target_role,
            timestamp=result.timestamp
        )
    except Exception as e:
        logger.error("Failed to record ping measurement: %s", e)


def poll_interface_background():
    """Background thread to sample interface counters while a session is running."""
    global active_interface_monitor, active_ping_monitor
    while True:
        with monitor_lock:
            if active_ping_monitor and active_ping_monitor.is_running and active_interface_monitor:
                try:
                    snapshot = active_interface_monitor.capture_snapshot()
                    record_interface_stats(snapshot)
                except Exception as e:
                    logger.debug("Interface poll failed: %s", e)
        threading.Event().wait(2.0)


# Start interface monitoring thread
if_thread = threading.Thread(target=poll_interface_background, name="InterfacePoller", daemon=True)
if_thread.start()


# ============================================================================
# Frontend Web Routes (HTML Views)
# ============================================================================

@app.route("/")
@app.route("/index")
def index_view():
    """System overview and quick launch page."""
    interfaces = get_all_interfaces_summary()
    active_session = get_active_session()
    tshark_path = find_tshark_binary()
    all_sessions = get_all_sessions(limit=5)
    return render_template(
        "index.html",
        interfaces=interfaces,
        active_session=active_session,
        tshark_installed=tshark_path is not None,
        tshark_path=tshark_path,
        recent_sessions=all_sessions,
        disclaimer=PHYSICAL_LAYER_DISCLAIMER
    )


@app.route("/dashboard")
def dashboard_view():
    """Real-time network monitoring dashboard with Chart.js visualization."""
    interfaces = get_all_interfaces_summary()
    active_session = get_active_session()
    return render_template(
        "dashboard.html",
        interfaces=interfaces,
        active_session=active_session,
        disclaimer=PHYSICAL_LAYER_DISCLAIMER
    )


@app.route("/investigation")
def investigation_view():
    """Structured electrical interference investigation workflow & Test A/B/C/D."""
    incidents = get_incidents()
    sessions = get_all_sessions(limit=20)
    return render_template(
        "investigation.html",
        incidents=incidents,
        sessions=sessions,
        disclaimer=PHYSICAL_LAYER_DISCLAIMER
    )


@app.route("/topology")
def topology_view():
    """Interactive visual network topology with hop-by-hop latency isolation."""
    interfaces = get_all_interfaces_summary()
    return render_template(
        "topology.html",
        interfaces=interfaces
    )


@app.route("/reports")
def reports_view():
    """Historical sessions, generated reports, CSV exports, and PDF downloads."""
    sessions = get_all_sessions(limit=50)
    incidents = get_incidents()
    captures = get_packet_captures()
    return render_template(
        "reports.html",
        sessions=sessions,
        incidents=incidents,
        captures=captures
    )


# ============================================================================
# Monitoring Control API Endpoints
# ============================================================================

@app.route("/api/system/status", methods=["GET"])
def api_system_status():
    """System tools readiness inspection."""
    interfaces = get_all_interfaces_summary()
    tshark_bin = find_tshark_binary()
    return jsonify({
        "platform": sys.platform,
        "tshark_installed": tshark_bin is not None,
        "tshark_path": tshark_bin,
        "interfaces_count": len(interfaces),
        "database_active": True,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """Return list of network interfaces."""
    return jsonify(get_all_interfaces_summary())


@app.route("/api/monitoring/start", methods=["POST"])
def api_start_monitoring():
    """
    Start continuous network monitoring.
    Validates targets, configures intervals, duration, and packet count limits.
    """
    global active_ping_monitor, active_interface_monitor

    with monitor_lock:
        if active_ping_monitor and active_ping_monitor.is_running:
            return jsonify({"success": False, "error": "A monitoring session is already active."}), 400

        data = request.get_json() or {}
        target = data.get("target", "").strip()
        mode = data.get("mode", "single")  # 'single', 'continuous', 'multi_target'
        interval_sec = float(data.get("interval_sec", 1.0))
        duration_sec = int(data.get("duration_sec", 60))
        packet_count = data.get("packet_count")
        if packet_count:
            packet_count = int(packet_count)
        timeout_sec = float(data.get("timeout_sec", 2.0))
        interface_name = data.get("interface_name", "")
        session_name = data.get("name") or f"Investigation {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # 11-hour investigation check
        if data.get("preset_11h"):
            duration_sec = 39600  # 11 hours
            mode = "continuous"

        try:
            clean_target = validate_target(target)
        except ValueError as ve:
            return jsonify({"success": False, "error": str(ve)}), 400

        # Build target list
        targets = [{"target": clean_target, "role": "target"}]
        if mode == "multi_target":
            gateway = data.get("gateway", "").strip()
            local_peer = data.get("local_peer", "").strip()
            dns_server = data.get("dns_server", "8.8.8.8").strip()
            internet_dest = data.get("internet_dest", "1.1.1.1").strip()

            if gateway:
                try:
                    targets.append({"target": validate_target(gateway), "role": "gateway"})
                except ValueError:
                    pass
            if local_peer:
                try:
                    targets.append({"target": validate_target(local_peer), "role": "local_peer"})
                except ValueError:
                    pass
            if dns_server:
                try:
                    targets.append({"target": validate_target(dns_server), "role": "dns"})
                except ValueError:
                    pass
            if internet_dest:
                try:
                    targets.append({"target": validate_target(internet_dest), "role": "internet"})
                except ValueError:
                    pass

        # Create session in DB
        session_id = create_session(
            name=session_name,
            target=clean_target,
            interval_sec=interval_sec,
            duration_sec=duration_sec,
            packet_count=packet_count,
            timeout_sec=timeout_sec,
            mode=mode,
            notes=data.get("notes", ""),
            is_demo=0
        )
        start_session(session_id)

        # Initialize Monitors
        active_ping_monitor = PingMonitor(
            session_id=session_id,
            targets=targets,
            interval_sec=interval_sec,
            duration_sec=duration_sec if mode != "continuous" else None,
            packet_limit=packet_count,
            timeout_sec=timeout_sec,
            on_result_callback=db_ping_callback
        )
        active_ping_monitor.start()

        if interface_name:
            active_interface_monitor = InterfaceStatsMonitor(
                interface_name=interface_name,
                session_id=session_id
            )

        logger.info("Successfully started monitoring session %d for target %s", session_id, clean_target)
        return jsonify({
            "success": True,
            "session_id": session_id,
            "target": clean_target,
            "mode": mode,
            "duration_sec": duration_sec
        })


@app.route("/api/monitoring/stop", methods=["POST"])
def api_stop_monitoring():
    """Stop active monitoring session immediately."""
    global active_ping_monitor, active_interface_monitor

    with monitor_lock:
        if not active_ping_monitor or not active_ping_monitor.is_running:
            return jsonify({"success": False, "error": "No monitoring session is currently running."}), 400

        sid = active_ping_monitor.session_id
        active_ping_monitor.stop()
        end_session(sid, status="stopped")

        logger.info("Stopped monitoring session %d upon user request.", sid)
        return jsonify({"success": True, "session_id": sid, "status": "stopped"})


@app.route("/api/dashboard/live", methods=["GET"])
def api_dashboard_live():
    """
    Live real-time polling endpoint.
    Returns current KPIs, multi-target latency, recent measurements, and interface stats delta.
    """
    global active_ping_monitor, active_interface_monitor

    with monitor_lock:
        if active_ping_monitor:
            snapshot = active_ping_monitor.get_live_snapshot()
            sid = active_ping_monitor.session_id
        else:
            active_sess = get_active_session()
            if active_sess:
                sid = active_sess["id"]
                summary = get_ping_summary(sid)
                snapshot = {
                    "session_id": sid,
                    "is_running": False,
                    "elapsed_sec": 0,
                    "duration_str": "00:00:00",
                    "primary_target": active_sess["target"],
                    "primary_stats": {
                        "target": active_sess["target"],
                        "current_rtt": summary.get("avg_rtt"),
                        "avg_rtt": summary.get("avg_rtt"),
                        "min_rtt": summary.get("min_rtt"),
                        "max_rtt": summary.get("max_rtt"),
                        "packets_sent": summary.get("total_packets"),
                        "packets_received": summary.get("successful_packets"),
                        "packets_lost": summary.get("lost_packets"),
                        "loss_pct": summary.get("loss_pct"),
                        "status": "idle"
                    },
                    "all_targets": [],
                    "overall_status": "idle"
                }
            else:
                return jsonify({
                    "is_running": False,
                    "overall_status": "idle",
                    "duration_str": "00:00:00",
                    "primary_stats": {
                        "packets_sent": 0, "packets_received": 0, "packets_lost": 0,
                        "loss_pct": 0.0, "current_rtt": 0.0, "avg_rtt": 0.0,
                        "min_rtt": 0.0, "max_rtt": 0.0
                    },
                    "recent_measurements": [],
                    "interface_stats": None
                })

    # Fetch recent measurements for Chart.js streaming
    recent_pings = get_recent_ping_measurements(sid, limit=60)
    recent_if = get_recent_interface_stats(session_id=sid, limit=1)
    if_data = recent_if[0] if recent_if else None

    return jsonify({
        **snapshot,
        "recent_measurements": recent_pings,
        "interface_stats": if_data
    })


# ============================================================================
# Incident & Comparative Investigation API Endpoints
# ============================================================================

@app.route("/api/incidents", methods=["GET", "POST"])
def api_incidents_handler():
    """Create or list electrical interference incidents."""
    if request.method == "POST":
        data = request.get_json() or {}
        incident_id = create_incident(data)
        return jsonify({"success": True, "incident_id": incident_id})
    else:
        return jsonify(get_incidents())


@app.route("/api/incidents/<int:incident_id>", methods=["GET"])
def api_incident_detail(incident_id):
    """Retrieve details and comparative tests for a specific incident."""
    incident = get_incident(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    tests = get_comparative_tests(incident_id)
    return jsonify({
        "incident": incident,
        "tests": tests
    })


@app.route("/api/incidents/<int:incident_id>/tests", methods=["POST"])
def api_add_comparative_test(incident_id):
    """Record a comparative test observation (Test A, B, C, or D)."""
    data = request.get_json() or {}
    data["incident_id"] = incident_id
    test_id = record_comparative_test(data)
    return jsonify({"success": True, "test_id": test_id})


@app.route("/api/analysis/correlate", methods=["POST"])
def api_run_correlation():
    """
    Execute the scientific correlation engine on session/incident data.
    Classifies root cause, scores confidence, and persists diagnosis.
    """
    data = request.get_json() or {}
    session_id = data.get("session_id")
    incident_id = data.get("incident_id")

    if not session_id and not incident_id:
        return jsonify({"error": "session_id or incident_id required."}), 400

    measurements = []
    if session_id:
        measurements = get_session_ping_measurements(session_id)
    tests = []
    if incident_id:
        tests = get_comparative_tests(incident_id)

    # Split measurements into baseline and incident periods
    mid = len(measurements) // 2 if len(measurements) > 1 else 1
    base_pings = measurements[:mid]
    inc_pings = measurements[mid:]

    recent_if = get_recent_interface_stats(session_id=session_id, limit=1)
    if_deltas = {}
    if recent_if:
        latest = recent_if[0]
        if_deltas = {
            "crc_fcs_delta": latest.get("crc_fcs_delta", 0),
            "rx_errors_delta": latest.get("rx_errors_delta", 0),
            "rx_drops_delta": latest.get("rx_drops_delta", 0)
        }

    engine = InvestigationCorrelationEngine()
    diag = engine.analyze_investigation(
        baseline_pings=base_pings,
        incident_pings=inc_pings,
        comparative_tests=tests,
        interface_stats_deltas=if_deltas
    )

    result_id = record_analysis_result({
        "session_id": session_id,
        "incident_id": incident_id,
        "category": diag.category.value,
        "confidence_score": diag.confidence_score,
        "rtt_baseline_avg": diag.metrics_snapshot.get("baseline", {}).get("stats", {}).get("mean", 0.0),
        "rtt_incident_avg": diag.metrics_snapshot.get("incident", {}).get("stats", {}).get("mean", 0.0),
        "rtt_delta_pct": diag.metrics_snapshot.get("deltas", {}).get("rtt_delta_pct", 0.0),
        "loss_baseline_pct": diag.metrics_snapshot.get("baseline", {}).get("loss_pct", 0.0),
        "loss_incident_pct": diag.metrics_snapshot.get("incident", {}).get("loss_pct", 0.0),
        "crc_fcs_total_delta": if_deltas.get("crc_fcs_delta", 0),
        "findings": diag.detailed_findings,
        "recommendations": diag.remediation_recommendations
    })

    return jsonify({
        "success": True,
        "analysis_id": result_id,
        "diagnosis": diag.to_dict()
    })


# ============================================================================
# Packet Capture API Endpoints
# ============================================================================

@app.route("/api/captures/interfaces", methods=["GET"])
def api_capture_interfaces():
    """List interfaces available for packet capture."""
    return jsonify(get_tshark_interfaces())


@app.route("/api/captures/start", methods=["POST"])
def api_start_capture():
    """Start packet capture on authorized interface."""
    data = request.get_json() or {}
    interface_id = data.get("interface_id", "1")
    duration = int(data.get("duration_sec", 60))
    limit = int(data.get("packet_limit", 5000))
    res = capture_manager.start_capture(interface_id=interface_id, duration_sec=duration, packet_limit=limit)
    return jsonify(res)


@app.route("/api/captures/stop", methods=["POST"])
def api_stop_capture():
    """Stop active packet capture and analyze contents."""
    res = capture_manager.stop_capture()
    if res.get("filename"):
        record_packet_capture(res)
    return jsonify(res)


@app.route("/api/captures/upload", methods=["POST"])
def api_upload_capture():
    """Upload and dissect an existing PCAP/PCAPNG capture file."""
    if "pcap_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["pcap_file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    safe_name = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    save_path = os.path.join(CAPTURES_DIR, safe_name)
    file.save(save_path)

    analysis = capture_manager.analyze_file(save_path)
    analysis["session_id"] = request.form.get("session_id")
    record_packet_capture(analysis)
    return jsonify(analysis)


# ============================================================================
# SNMP Switch Monitoring Endpoints
# ============================================================================

@app.route("/api/snmp/poll", methods=["POST"])
def api_snmp_poll():
    """Poll managed switch port counters via SNMP."""
    data = request.get_json() or {}
    host = data.get("host", "192.168.1.1").strip()
    port = int(data.get("port", 161))
    community = data.get("community", "public").strip()
    if_index = int(data.get("if_index", 1))

    monitor = SnmpSwitchMonitor(host=host, community=community, port=port, if_index=if_index)
    res = monitor.poll_port_counters()
    return jsonify(res)


# ============================================================================
# Report Generation & Download API Endpoints
# ============================================================================

@app.route("/api/reports/csv/<int:session_id>", methods=["GET"])
def api_download_csv(session_id):
    """Download CSV file of raw ping and sequence data."""
    csv_data = generate_csv_report(session_id)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=session_{session_id}_measurements.csv"}
    )


@app.route("/api/reports/pdf/<int:session_id>", methods=["GET"])
def api_download_pdf(session_id):
    """Generate and return technical PDF investigation report."""
    incident_id = request.args.get("incident_id")
    if incident_id:
        incident_id = int(incident_id)

    try:
        pdf_path = generate_pdf_report(session_id=session_id, incident_id=incident_id)
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"investigation_report_session_{session_id}.pdf"
        )
    except Exception as e:
        logger.error("Failed to generate PDF: %s", e)
        return jsonify({"error": f"Failed to generate PDF report: {e}"}), 500


@app.route("/api/demo/seed", methods=["POST"])
def api_seed_demo():
    """Seed benchmark demonstration dataset."""
    sid = seed_all_demo_data()
    return jsonify({"success": True, "session_id": sid, "message": "Benchmark dataset seeded successfully."})


# ============================================================================
# Application Entrypoint
# ============================================================================

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Electrical Interference Investigation Tool on http://127.0.0.1:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
