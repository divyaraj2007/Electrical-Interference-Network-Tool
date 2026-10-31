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
    save_snmp_config, get_snmp_configs,
    upsert_device, get_device_by_id, get_device_by_token, get_all_devices,
    update_device_heartbeat, update_device_status, delete_device,
    create_agent_task, get_pending_agent_tasks, update_agent_task,
    create_two_device_test, get_two_device_test, get_two_device_test_by_uuid,
    update_two_device_test, get_all_two_device_tests, record_two_device_measurement,
    get_two_device_measurements, record_two_device_analysis, get_two_device_analysis,
    DEFAULT_DB_PATH
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
from analysis.two_device_analysis import analyze_two_device_test, TwoDeviceRootCause
from reports.report_generator import generate_csv_report, generate_pdf_report
from reports.two_device_report import generate_two_device_csv, generate_two_device_pdf
from agents.common.security import generate_device_token, validate_device_id, validate_ip_or_hostname
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


@app.route("/devices")
def device_management_view():
    """Device registration and connection management view."""
    devices = get_all_devices()
    return render_template(
        "device_management.html",
        devices=devices,
        disclaimer=PHYSICAL_LAYER_DISCLAIMER
    )


@app.route("/two-device-testing")
def two_device_testing_view():
    """Coordinated Two-Device Testing Dashboard view."""
    devices = get_all_devices()
    incidents = get_incidents()
    tests = get_all_two_device_tests(limit=20)
    return render_template(
        "two_device_testing.html",
        devices=devices,
        incidents=incidents,
        tests=tests,
        disclaimer=PHYSICAL_LAYER_DISCLAIMER
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
# Two-Device System & Device Management API Endpoints
# ============================================================================

active_two_device_tests: Dict[int, Dict[str, Any]] = {}
active_two_lock = threading.Lock()


@app.route("/api/devices", methods=["GET"])
def api_list_devices():
    """List all registered Sender and Receiver devices."""
    devices = get_all_devices()
    return jsonify({
        "success": True,
        "count": len(devices),
        "devices": devices
    })


@app.route("/api/devices/token/generate", methods=["GET"])
def api_generate_token():
    """Generate a new secure authentication token for agent onboarding."""
    return jsonify({
        "success": True,
        "token": generate_device_token()
    })


@app.route("/api/devices/register", methods=["POST"])
def api_register_device():
    """Register or update a Sender or Receiver agent device."""
    data = request.get_json() or {}
    device_id = data.get("device_id")
    if not device_id:
        # Auto-generate a device ID if not provided
        role = data.get("device_type", "sender")
        import uuid
        device_id = f"{role}-{uuid.uuid4().hex[:8]}"
        data["device_id"] = device_id

    try:
        clean_id = validate_device_id(device_id)
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400

    token = data.get("auth_token") or generate_device_token()
    data["auth_token"] = token
    data["device_id"] = clean_id

    device = upsert_device(data)
    logger.info("Registered agent device %s (%s)", clean_id, data.get("device_type", "sender"))
    return jsonify({
        "success": True,
        "device": device,
        "auth_token": token
    })


@app.route("/api/devices/<device_id>", methods=["GET"])
def api_get_device(device_id):
    """Retrieve detailed information for a specific device."""
    device = get_device_by_id(device_id)
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404
    return jsonify({"success": True, "device": device})


@app.route("/api/devices/<device_id>/reconnect", methods=["POST"])
def api_reconnect_device(device_id):
    """Reset device connectivity status and allow reconnecting."""
    device = get_device_by_id(device_id)
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404
    update_device_status(device_id, "online")
    return jsonify({"success": True, "message": f"Device {device_id} status reset to online."})


@app.route("/api/devices/<device_id>", methods=["DELETE"])
def api_delete_device(device_id):
    """Remove a device registration."""
    success = delete_device(device_id)
    return jsonify({"success": success})


@app.route("/api/devices/heartbeat", methods=["POST"])
def api_device_heartbeat():
    """Agent heartbeat endpoint with real-time hardware telemetry."""
    data = request.get_json() or {}
    device_id = data.get("device_id") or request.headers.get("X-Device-ID")
    token = request.headers.get("X-Device-Token")

    if not device_id:
        return jsonify({"success": False, "error": "Missing device_id"}), 400

    device = get_device_by_id(device_id)
    if not device:
        return jsonify({"success": False, "error": "Unknown device"}), 404

    # Validate authentication token if set
    if device.get("auth_token") and token and device["auth_token"] != token:
        return jsonify({"success": False, "error": "Invalid authentication token"}), 401

    update_device_heartbeat(device_id, data)
    return jsonify({"success": True, "status": "acknowledged"})


@app.route("/api/devices/<device_id>/tasks", methods=["GET"])
def api_device_fetch_tasks(device_id):
    """Poll for pending tasks queued for this agent."""
    device = get_device_by_id(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    token = request.headers.get("X-Device-Token")
    if device.get("auth_token") and token and device["auth_token"] != token:
        return jsonify({"error": "Unauthorized"}), 401

    tasks = get_pending_agent_tasks(device_id)
    return jsonify({"success": True, "tasks": tasks})


@app.route("/api/devices/<device_id>/results", methods=["POST"])
def api_device_post_results(device_id):
    """Receive completed test results from an agent."""
    data = request.get_json() or {}
    task_id = data.get("task_id")
    status = data.get("status", "completed")
    result = data.get("result", {})

    update_agent_task(task_id, status=status, result=result)

    # Correlate with active two-device test if applicable
    with active_two_lock:
        for tid, test_state in list(active_two_device_tests.items()):
            if test_state.get("sender_task_id") == task_id:
                test_state["sender_result"] = result
                test_state["sender_reported"] = True
                # Record sender measurements
                record_two_device_measurement({
                    "test_id": tid,
                    "device_id": device_id,
                    "device_role": "sender",
                    "metric_type": "full_suite",
                    "data": result,
                    "value_numeric": result.get("metrics", {}).get("ping", {}).get("avg_rtt_ms", 0.0)
                })

            elif test_state.get("receiver_task_id") == task_id:
                test_state["receiver_result"] = result
                test_state["receiver_reported"] = True
                # Record receiver measurements
                record_two_device_measurement({
                    "test_id": tid,
                    "device_id": device_id,
                    "device_role": "receiver",
                    "metric_type": "full_suite",
                    "data": result,
                    "value_numeric": result.get("incoming_traffic", {}).get("measured_throughput_mbps", 0.0)
                })

            # If both reported, finalize the test
            if test_state.get("sender_reported") and test_state.get("receiver_reported"):
                _finalize_two_device_test(tid, test_state)

    return jsonify({"success": True, "message": "Results recorded successfully."})


@app.route("/api/devices/<device_id>/telemetry", methods=["POST"])
def api_device_post_telemetry(device_id):
    """Receive live telemetry point from an agent."""
    data = request.get_json() or {}
    # Record individual live telemetry measurement
    test_id = data.get("test_id")
    if test_id:
        record_two_device_measurement({
            "test_id": int(test_id),
            "device_id": device_id,
            "device_role": data.get("role", "sender"),
            "metric_type": data.get("metric_type", "telemetry"),
            "data": data,
            "value_numeric": float(data.get("value", 0.0))
        })
    return jsonify({"success": True})


def _finalize_two_device_test(test_id: int, test_state: Dict[str, Any]):
    """Execute analysis and finalize two-device test in database."""
    s_res = test_state.get("sender_result") or {}
    r_res = test_state.get("receiver_result") or {}
    eq_state = test_state.get("equipment_state", "off")
    inc_id = test_state.get("incident_id")

    # Run root cause classification
    diag = analyze_two_device_test(
        sender_results=s_res,
        receiver_results=r_res,
        equipment_state=eq_state
    )

    s_ping = s_res.get("metrics", {}).get("ping", {})
    s_tcp = s_res.get("metrics", {}).get("tcp_throughput", {})
    r_traffic = r_res.get("incoming_traffic", {})
    s_if = s_res.get("interface_deltas", {})
    r_if = r_res.get("interface_deltas", {})

    record_two_device_analysis({
        "test_id": test_id,
        "incident_id": inc_id,
        "category": diag.category.value,
        "confidence_score": diag.confidence_score,
        "rtt_avg": s_ping.get("avg_rtt_ms", 0.0),
        "jitter_ms": s_ping.get("jitter_ms", 0.0),
        "loss_pct": s_ping.get("loss_pct", 0.0),
        "sender_throughput_mbps": s_tcp.get("throughput_mbps", 0.0),
        "receiver_throughput_mbps": r_traffic.get("measured_throughput_mbps", s_tcp.get("throughput_mbps", 0.0)),
        "retransmissions": s_tcp.get("retransmissions", 0),
        "sender_errors_delta": s_if.get("rx_errors_delta", 0) + s_if.get("tx_errors_delta", 0),
        "receiver_errors_delta": r_if.get("rx_errors_delta", 0) + r_if.get("tx_errors_delta", 0),
        "sender_crc_delta": s_if.get("crc_delta", 0),
        "receiver_crc_delta": r_if.get("crc_delta", 0),
        "findings": diag.detailed_findings,
        "recommendations": diag.remediation_recommendations
    })

    summary = {
        "sender": s_res,
        "receiver": r_res,
        "diagnosis": diag.to_dict()
    }

    now_utc = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    update_two_device_test(test_id, {
        "status": "completed",
        "end_time": now_utc,
        "summary": summary
    })
    update_device_status(test_state["sender_device_id"], "online")
    update_device_status(test_state["receiver_device_id"], "online")
    logger.info("Two-Device Test %d successfully finalized and analyzed.", test_id)


# ============================================================================
# Coordinated Two-Device Testing Control Endpoints
# ============================================================================

@app.route("/api/two-device/tests/preflight", methods=["POST"])
def api_two_device_preflight():
    """Verify connectivity between selected Sender and Receiver devices."""
    data = request.get_json() or {}
    s_id = data.get("sender_device_id")
    r_id = data.get("receiver_device_id")

    if not s_id or not r_id:
        return jsonify({"success": False, "error": "Sender and Receiver device IDs required"}), 400

    sender = get_device_by_id(s_id)
    receiver = get_device_by_id(r_id)

    if not sender or not receiver:
        return jsonify({"success": False, "error": "One or both devices not registered"}), 404

    # Check online status
    s_online = sender.get("status") == "online"
    r_online = receiver.get("status") == "online"

    # Quick socket or ping check to receiver IP
    r_ip = receiver.get("ip_address", "127.0.0.1")
    reachable = True
    rtt_ms = 1.0

    try:
        from monitoring.ping_monitor import ping_single
        ping_res = ping_single(r_ip, timeout_sec=2.0)
        reachable = ping_res.success
        rtt_ms = ping_res.rtt_ms or 1.0
    except Exception:
        pass

    return jsonify({
        "success": True,
        "sender": {"id": s_id, "online": s_online, "ip": sender.get("ip_address")},
        "receiver": {"id": r_id, "online": r_online, "ip": r_ip},
        "reachable": reachable,
        "rtt_ms": rtt_ms,
        "message": "Pre-flight connectivity verified successfully." if (s_online and r_online and reachable) else "Pre-flight warnings detected."
    })


@app.route("/api/two-device/tests/create", methods=["POST"])
def api_two_device_create_test():
    """Create and remotely initiate a coordinated two-device network test."""
    data = request.get_json() or {}
    s_id = data.get("sender_device_id")
    r_id = data.get("receiver_device_id")

    if not s_id or not r_id:
        return jsonify({"success": False, "error": "sender_device_id and receiver_device_id are required"}), 400

    sender = get_device_by_id(s_id)
    receiver = get_device_by_id(r_id)

    if not sender or not receiver:
        return jsonify({"success": False, "error": "Sender or Receiver device not found"}), 404

    import uuid
    test_uuid = str(uuid.uuid4())
    direction = data.get("direction", "sender_to_receiver")
    duration = int(data.get("duration_sec", 15))
    packet_size = int(data.get("packet_size_bytes", 64))
    interval = float(data.get("interval_sec", 0.5))
    eq_state = data.get("equipment_state", "off")
    inc_id = data.get("incident_id")
    test_modes = data.get("test_modes", ["icmp_ping", "rtt", "jitter", "loss", "tcp_throughput"])

    # Persist in DB
    test_id = create_two_device_test({
        "test_uuid": test_uuid,
        "name": data.get("name") or f"Two-Device Test ({sender.get('hostname')} -> {receiver.get('hostname')})",
        "incident_id": inc_id,
        "sender_device_id": s_id,
        "receiver_device_id": r_id,
        "direction": direction,
        "test_modes": test_modes,
        "duration_sec": duration,
        "packet_size_bytes": packet_size,
        "interval_sec": interval,
        "equipment_state": eq_state
    })

    now_utc = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    update_two_device_test(test_id, {"status": "running", "start_time": now_utc})
    update_device_status(s_id, "testing")
    update_device_status(r_id, "testing")

    # Queue tasks for Sender and Receiver
    s_task_id = str(uuid.uuid4())
    r_task_id = str(uuid.uuid4())

    create_agent_task(
        device_id=s_id,
        task_type="run_test",
        payload={
            "test_id": test_id,
            "test_uuid": test_uuid,
            "receiver_ip": receiver.get("ip_address", "127.0.0.1"),
            "sender_ip": sender.get("ip_address", "127.0.0.1"),
            "test_modes": test_modes,
            "duration_sec": duration,
            "packet_size_bytes": packet_size,
            "interval_sec": interval,
            "direction": direction,
            "iperf_port": 5201
        },
        task_id=s_task_id
    )

    create_agent_task(
        device_id=r_id,
        task_type="run_test",
        payload={
            "test_id": test_id,
            "test_uuid": test_uuid,
            "sender_ip": sender.get("ip_address", "127.0.0.1"),
            "receiver_ip": receiver.get("ip_address", "127.0.0.1"),
            "test_modes": test_modes,
            "duration_sec": duration,
            "packet_size_bytes": packet_size,
            "interval_sec": interval,
            "direction": direction,
            "iperf_port": 5201
        },
        task_id=r_task_id
    )

    with active_two_lock:
        active_two_device_tests[test_id] = {
            "test_id": test_id,
            "test_uuid": test_uuid,
            "sender_device_id": s_id,
            "receiver_device_id": r_id,
            "sender_task_id": s_task_id,
            "receiver_task_id": r_task_id,
            "sender_reported": False,
            "receiver_reported": False,
            "sender_result": None,
            "receiver_result": None,
            "duration_sec": duration,
            "equipment_state": eq_state,
            "incident_id": inc_id,
            "start_time": now_utc
        }

    # Launch watchdog thread to auto-finalize if an agent times out
    def _watchdog():
        time.sleep(duration + 12.0)
        with active_two_lock:
            state = active_two_device_tests.get(test_id)
            if state and (not state.get("sender_reported") or not state.get("receiver_reported")):
                logger.info("Watchdog completing two-device test %d after timeout.", test_id)
                _finalize_two_device_test(test_id, state)

    threading.Thread(target=_watchdog, daemon=True).start()

    logger.info("Initiated Two-Device Test %d (%s) across %s and %s", test_id, test_uuid, s_id, r_id)
    return jsonify({
        "success": True,
        "test_id": test_id,
        "test_uuid": test_uuid,
        "duration_sec": duration,
        "direction": direction,
        "status": "running"
    })


@app.route("/api/two-device/tests/<int:test_id>/stop", methods=["POST"])
def api_two_device_stop_test(test_id):
    """Remotely stop an active two-device test."""
    test = get_two_device_test(test_id)
    if not test:
        return jsonify({"success": False, "error": "Test not found"}), 404

    now_utc = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    update_two_device_test(test_id, {"status": "stopped", "end_time": now_utc})
    update_device_status(test["sender_device_id"], "online")
    update_device_status(test["receiver_device_id"], "online")

    with active_two_lock:
        if test_id in active_two_device_tests:
            del active_two_device_tests[test_id]

    return jsonify({"success": True, "message": f"Test {test_id} stopped."})


@app.route("/api/two-device/tests/<int:test_id>/status", methods=["GET"])
def api_two_device_test_status(test_id):
    """Retrieve execution status and live progress of a two-device test."""
    test = get_two_device_test(test_id)
    if not test:
        return jsonify({"success": False, "error": "Test not found"}), 404

    measurements = get_two_device_measurements(test_id, limit=50)
    analysis = get_two_device_analysis(test_id)

    return jsonify({
        "success": True,
        "test": test,
        "status": test.get("status"),
        "recent_measurements": measurements,
        "analysis": analysis
    })


@app.route("/api/two-device/tests/<int:test_id>/results", methods=["GET"])
def api_two_device_test_results(test_id):
    """Return complete combined test results, device comparisons, and root-cause analysis."""
    test = get_two_device_test(test_id)
    if not test:
        return jsonify({"success": False, "error": "Test not found"}), 404

    sender = get_device_by_id(test["sender_device_id"]) or {}
    receiver = get_device_by_id(test["receiver_device_id"]) or {}
    analysis = get_two_device_analysis(test_id)
    summary = test.get("summary") or {}

    return jsonify({
        "success": True,
        "test": test,
        "sender_device": sender,
        "receiver_device": receiver,
        "summary": summary,
        "analysis": analysis
    })


@app.route("/api/two-device/tests", methods=["GET"])
def api_two_device_tests_list():
    """List historical two-device tests."""
    tests = get_all_two_device_tests(limit=50)
    return jsonify({
        "success": True,
        "count": len(tests),
        "tests": tests
    })


# ============================================================================
# Real-Time Telemetry Stream (Server-Sent Events)
# ============================================================================

@app.route("/api/devices/stream", methods=["GET"])
def api_devices_stream():
    """Server-Sent Events (SSE) streaming real-time device telemetry and test progress."""
    def event_stream():
        while True:
            try:
                devices = get_all_devices()
                # Check active test
                active_test = None
                with active_two_lock:
                    if active_two_device_tests:
                        latest_tid = list(active_two_device_tests.keys())[-1]
                        active_test = active_two_device_tests[latest_tid]

                payload = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "devices": devices,
                    "active_test": active_test
                }
                yield f"data: {json.dumps(payload)}\n\n"
            except Exception as e:
                logger.debug("SSE stream error: %s", e)
                break
            time.sleep(1.0)

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


# ============================================================================
# Two-Device Report Exports (CSV & PDF)
# ============================================================================

@app.route("/api/two-device/reports/csv/<int:test_id>", methods=["GET"])
def api_two_device_download_csv(test_id):
    """Download CSV export of two-device measurements."""
    try:
        csv_data = generate_two_device_csv(test_id)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=two_device_test_{test_id}_measurements.csv"}
        )
    except Exception as e:
        logger.error("Failed to generate CSV: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/two-device/reports/pdf/<int:test_id>", methods=["GET"])
def api_two_device_download_pdf(test_id):
    """Generate and return technical PDF investigation report for two-device test."""
    try:
        pdf_path = generate_two_device_pdf(test_id)
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"two_device_investigation_report_test_{test_id}.pdf"
        )
    except Exception as e:
        logger.error("Failed to generate PDF: %s", e)
        return jsonify({"error": f"Failed to generate PDF report: {e}"}), 500


@app.route("/api/two-device/demo/seed", methods=["POST"])
def api_two_device_demo_seed():
    """Seed benchmark two-device dataset demonstrating industrial VFD interference."""
    sid = seed_two_device_benchmark_data()
    return jsonify({
        "success": True,
        "test_id": sid,
        "message": "Two-Device benchmark dataset seeded successfully."
    })


def seed_two_device_benchmark_data() -> int:
    """Helper to populate realistic two-device benchmark data with VFD interference."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Upsert Sender Device
    sender = upsert_device({
        "device_id": "sender-node-demo",
        "device_type": "sender",
        "hostname": "Workstation-Sender-Win11",
        "ip_address": "192.168.10.10",
        "os_info": "Windows 11 Pro (Build 22631)",
        "agent_version": "1.1.0",
        "auth_token": "demo-sender-token-12345",
        "active_interface": "Ethernet (Intel I219-V)",
        "link_speed_mbps": 1000,
        "cpu_pct": 14.5,
        "mem_pct": 38.2,
        "rx_errors": 0,
        "tx_errors": 0,
        "rx_drops": 0,
        "tx_drops": 0,
        "crc_fcs_errors": 0,
        "crc_supported": 0
    })

    # 2. Upsert Receiver Device
    receiver = upsert_device({
        "device_id": "receiver-node-demo",
        "device_type": "receiver",
        "hostname": "Industrial-Receiver-Ubuntu",
        "ip_address": "192.168.10.20",
        "os_info": "Ubuntu 24.04 LTS (x86_64)",
        "agent_version": "1.1.0",
        "auth_token": "demo-receiver-token-67890",
        "active_interface": "enp3s0 (Intel I225-V)",
        "link_speed_mbps": 1000,
        "cpu_pct": 18.2,
        "mem_pct": 42.1,
        "rx_errors": 18,
        "tx_errors": 0,
        "rx_drops": 4,
        "tx_drops": 0,
        "crc_fcs_errors": 18,
        "crc_supported": 1
    })

    # 3. Create Two-Device Test record
    import uuid
    test_id = create_two_device_test({
        "test_uuid": f"demo-two-dev-vfd-{uuid.uuid4().hex[:8]}",
        "name": f"Benchmark Two-Device VFD Interference Investigation ({datetime.now().strftime('%H:%M:%S')})",
        "sender_device_id": "sender-node-demo",
        "receiver_device_id": "receiver-node-demo",
        "direction": "sender_to_receiver",
        "test_modes": ["icmp_ping", "rtt", "jitter", "loss", "tcp_throughput", "mtu", "traceroute"],
        "duration_sec": 30,
        "packet_size_bytes": 64,
        "interval_sec": 0.5,
        "equipment_state": "on"
    })

    # 4. Synthesize realistic Sender & Receiver measurements
    sender_results = {
        "target": "192.168.10.20",
        "role": "sender",
        "direction": "sender_to_receiver",
        "duration_sec": 30,
        "metrics": {
            "ping": {
                "target": "192.168.10.20",
                "packets_sent": 60,
                "packets_received": 56,
                "packets_lost": 4,
                "loss_pct": 6.67,
                "min_rtt_ms": 0.42,
                "avg_rtt_ms": 4.85,
                "max_rtt_ms": 38.6,
                "jitter_ms": 7.42
            },
            "tcp_throughput": {
                "throughput_mbps": 340.5,
                "upload_mbps": 340.5,
                "download_mbps": 340.5,
                "retransmissions": 14,
                "jitter_ms": 7.42,
                "loss_pct": 6.67
            }
        },
        "interface_deltas": {
            "rx_errors_delta": 0,
            "tx_errors_delta": 0,
            "rx_drops_delta": 0,
            "tx_drops_delta": 0,
            "crc_delta": 0,
            "crc_supported": False,
            "crc_display": "Unsupported by OS/driver",
            "reset_detected": False
        },
        "system_usage": {
            "cpu_after": 14.5,
            "mem_after": 38.2
        }
    }

    receiver_results = {
        "target": "192.168.10.10",
        "role": "receiver",
        "direction": "sender_to_receiver",
        "duration_sec": 30,
        "incoming_traffic": {
            "bytes_received": 1276875000,
            "packets_received": 56,
            "measured_throughput_mbps": 340.5
        },
        "interface_deltas": {
            "rx_errors_delta": 18,
            "tx_errors_delta": 0,
            "rx_drops_delta": 4,
            "tx_drops_delta": 0,
            "crc_delta": 18,
            "crc_supported": True,
            "crc_display": "18",
            "reset_detected": False
        },
        "system_usage": {
            "cpu_after": 18.2,
            "mem_after": 42.1
        }
    }

    # Record measurement rows for charts
    for i in range(1, 31):
        rtt = 0.5 + (35.0 if 10 <= i <= 16 else 0.2 * (i % 5))
        loss = 1 if i in (11, 14) else 0
        record_two_device_measurement({
            "test_id": test_id,
            "device_id": "sender-node-demo",
            "device_role": "sender",
            "metric_type": "ping",
            "sequence_num": i,
            "value_numeric": rtt,
            "data": {"rtt_ms": rtt, "loss": loss, "jitter_ms": 6.8}
        })

    # Finalize test
    test_state = {
        "sender_result": sender_results,
        "receiver_result": receiver_results,
        "equipment_state": "on",
        "incident_id": None,
        "sender_device_id": "sender-node-demo",
        "receiver_device_id": "receiver-node-demo"
    }
    _finalize_two_device_test(test_id, test_state)
    return test_id



# ============================================================================
# Application Entrypoint
# ============================================================================

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Electrical Interference Investigation Tool on http://127.0.0.1:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
