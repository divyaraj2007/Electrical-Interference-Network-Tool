"""
Integration and End-to-End Tests for the Coordinated Two-Device Testing System.
Validates device management, task dispatching, root-cause diagnosis,
PDF/CSV exports, and Flask REST endpoints.
"""

import sys
import os
import json
import pytest
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from database.db import (
    init_db, upsert_device, get_device_by_id, get_all_devices,
    update_device_heartbeat, delete_device, create_agent_task,
    get_pending_agent_tasks, update_agent_task, create_two_device_test,
    get_two_device_test, update_two_device_test, record_two_device_measurement,
    record_two_device_analysis, get_two_device_analysis
)
from analysis.two_device_analysis import (
    analyze_two_device_test, TwoDeviceRootCause
)
from reports.two_device_report import generate_two_device_csv, generate_two_device_pdf


@pytest.fixture
def temp_db():
    """Create isolated temporary database for test suite."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path)
    yield path
    try:
        os.remove(path)
    except Exception:
        pass


@pytest.fixture
def test_client(temp_db):
    """Flask test client pointing to isolated test database."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_device_crud_operations(temp_db):
    """Verify device registration, retrieval, telemetry update, and deletion in SQLite."""
    dev_data = {
        "device_id": "sender-test-01",
        "device_type": "sender",
        "hostname": "Test-Sender-PC",
        "ip_address": "192.168.1.10",
        "os_info": "Ubuntu 24.04 LTS",
        "auth_token": "secret-test-token-1",
        "active_interface": "eth0",
        "link_speed_mbps": 1000
    }

    # 1. Register device
    dev = upsert_device(dev_data, db_path=temp_db)
    assert dev["device_id"] == "sender-test-01"
    assert dev["status"] == "online"

    # 2. Get device
    fetched = get_device_by_id("sender-test-01", db_path=temp_db)
    assert fetched is not None
    assert fetched["hostname"] == "Test-Sender-PC"

    # 3. Update heartbeat
    updated = update_device_heartbeat("sender-test-01", {
        "cpu_pct": 25.5,
        "mem_pct": 50.0,
        "rx_errors": 2,
        "crc_fcs_errors": 1,
        "crc_supported": 1
    }, db_path=temp_db)
    assert updated is True

    fetched_hb = get_device_by_id("sender-test-01", db_path=temp_db)
    assert fetched_hb["cpu_pct"] == 25.5
    assert fetched_hb["crc_supported"] == 1

    # 4. Delete device
    deleted = delete_device("sender-test-01", db_path=temp_db)
    assert deleted is True
    assert get_device_by_id("sender-test-01", db_path=temp_db) is None


def test_agent_task_queue(temp_db):
    """Verify queuing, dispatching, and completing tasks for agents."""
    task_id = create_agent_task(
        device_id="receiver-node-02",
        task_type="run_test",
        payload={"duration_sec": 10, "port": 5201},
        task_id="task-uuid-1234",
        db_path=temp_db
    )
    assert task_id > 0

    pending = get_pending_agent_tasks("receiver-node-02", db_path=temp_db)
    assert len(pending) == 1
    assert pending[0]["task_id"] == "task-uuid-1234"
    assert pending[0]["payload"]["duration_sec"] == 10

    # Subsequent call should return empty (status changed to dispatched)
    assert len(get_pending_agent_tasks("receiver-node-02", db_path=temp_db)) == 0

    # Mark completed
    res = update_agent_task("task-uuid-1234", status="completed", result={"throughput_mbps": 940.0}, db_path=temp_db)
    assert res is True


def test_root_cause_analysis_classification():
    """Verify the correlation engine accurately classifies physical and network anomalies."""

    # Scenario 1: Possible Physical EMI (high CRC and loss correlated with equipment ON)
    s_emi = {
        "metrics": {"ping": {"avg_rtt_ms": 12.0, "max_rtt_ms": 45.0, "jitter_ms": 8.0, "loss_pct": 8.5}},
        "interface_deltas": {"crc_delta": 15, "crc_supported": True, "rx_errors_delta": 15, "tx_errors_delta": 0, "rx_drops_delta": 0, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 20.0, "mem_after": 30.0}
    }
    r_emi = {
        "incoming_traffic": {"measured_throughput_mbps": 120.0},
        "interface_deltas": {"crc_delta": 12, "crc_supported": True, "rx_errors_delta": 12, "tx_errors_delta": 0, "rx_drops_delta": 0, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 22.0, "mem_after": 32.0}
    }
    diag1 = analyze_two_device_test(s_emi, r_emi, equipment_state="on")
    assert diag1.category == TwoDeviceRootCause.POSSIBLE_EMI
    assert diag1.confidence_score >= 80.0

    # Scenario 2: Sender-Side Resource Bottleneck (Sender 95% CPU and drops, clean receiver)
    s_bottleneck = {
        "metrics": {"ping": {"avg_rtt_ms": 5.0, "loss_pct": 1.0, "jitter_ms": 1.0}},
        "interface_deltas": {"crc_delta": 0, "crc_supported": False, "rx_errors_delta": 0, "tx_errors_delta": 0, "rx_drops_delta": 30, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 95.0, "mem_after": 40.0}
    }
    r_clean = {
        "incoming_traffic": {"measured_throughput_mbps": 500.0},
        "interface_deltas": {"crc_delta": 0, "crc_supported": True, "rx_errors_delta": 0, "tx_errors_delta": 0, "rx_drops_delta": 0, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 15.0, "mem_after": 25.0}
    }
    diag2 = analyze_two_device_test(s_bottleneck, r_clean, equipment_state="off")
    assert diag2.category == TwoDeviceRootCause.SENDER_SIDE_PROBLEM

    # Scenario 3: Network Congestion (High RTT without physical errors)
    s_congestion = {
        "metrics": {"ping": {"avg_rtt_ms": 65.0, "max_rtt_ms": 140.0, "jitter_ms": 22.0, "loss_pct": 1.0}},
        "interface_deltas": {"crc_delta": 0, "crc_supported": False, "rx_errors_delta": 0, "tx_errors_delta": 0, "rx_drops_delta": 0, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 20.0, "mem_after": 30.0}
    }
    r_congestion = {
        "incoming_traffic": {"measured_throughput_mbps": 40.0},
        "interface_deltas": {"crc_delta": 0, "crc_supported": False, "rx_errors_delta": 0, "tx_errors_delta": 0, "rx_drops_delta": 0, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 15.0, "mem_after": 25.0}
    }
    diag3 = analyze_two_device_test(s_congestion, r_congestion, equipment_state="off")
    assert diag3.category == TwoDeviceRootCause.NETWORK_CONGESTION

    # Scenario 4: Upstream Gateway / WAN failure (Local path fast, gateway failing)
    s_wan = {
        "metrics": {
            "ping": {"avg_rtt_ms": 0.8, "loss_pct": 0.0, "jitter_ms": 0.1},
            "gateway_ping": {"loss_pct": 35.0},
            "external_ping": {"loss_pct": 50.0}
        },
        "interface_deltas": {"crc_delta": 0, "crc_supported": False, "rx_errors_delta": 0, "tx_errors_delta": 0, "rx_drops_delta": 0, "tx_drops_delta": 0},
        "system_usage": {"cpu_after": 10.0, "mem_after": 20.0}
    }
    diag4 = analyze_two_device_test(s_wan, r_clean, equipment_state="off")
    assert diag4.category == TwoDeviceRootCause.GATEWAY_WAN_PROBLEM


def test_two_device_reports_csv_and_pdf(temp_db):
    """Verify CSV and publication-grade PDF report exports."""
    # Seed devices and test
    upsert_device({
        "device_id": "sender-pdf-01",
        "device_type": "sender",
        "hostname": "Host-Sender",
        "ip_address": "192.168.10.50",
        "os_info": "Windows 11",
        "auth_token": "token-1"
    }, db_path=temp_db)

    upsert_device({
        "device_id": "receiver-pdf-02",
        "device_type": "receiver",
        "hostname": "Host-Receiver",
        "ip_address": "192.168.10.60",
        "os_info": "Ubuntu 24.04",
        "auth_token": "token-2"
    }, db_path=temp_db)

    test_id = create_two_device_test({
        "test_uuid": "test-pdf-uuid-999",
        "name": "Integration PDF Report Test",
        "sender_device_id": "sender-pdf-01",
        "receiver_device_id": "receiver-pdf-02",
        "direction": "sender_to_receiver",
        "test_modes": ["icmp_ping", "tcp_throughput"],
        "duration_sec": 15,
        "equipment_state": "off"
    }, db_path=temp_db)

    # Record sample measurement
    record_two_device_measurement({
        "test_id": test_id,
        "device_id": "sender-pdf-01",
        "device_role": "sender",
        "metric_type": "ping",
        "sequence_num": 1,
        "value_numeric": 1.25,
        "data": {"rtt_ms": 1.25, "loss": 0}
    }, db_path=temp_db)

    # Record analysis
    record_two_device_analysis({
        "test_id": test_id,
        "category": "insufficient_evidence",
        "confidence_score": 85.0,
        "rtt_avg": 1.25,
        "jitter_ms": 0.1,
        "loss_pct": 0.0,
        "findings": ["Clean network operation with zero CRC errors."],
        "recommendations": ["No remediation required."]
    }, db_path=temp_db)

    # 1. Test CSV Generation
    csv_text = generate_two_device_csv(test_id, db_path=temp_db)
    assert "Record_ID,Timestamp_UTC,Device_Role" in csv_text
    assert "sender-pdf-01" in csv_text

    # 2. Test PDF Generation
    fd, pdf_out = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        pdf_path = generate_two_device_pdf(test_id, output_path=pdf_out, db_path=temp_db)
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 1000  # Valid non-empty PDF
    finally:
        try:
            os.remove(pdf_out)
        except Exception:
            pass


def test_flask_web_views_and_api(test_client):
    """Verify Flask routes respond correctly."""
    # Test HTML views
    res_devices = test_client.get("/devices")
    assert res_devices.status_code == 200
    assert b"Network Testing Device Management" in res_devices.data

    res_testing = test_client.get("/two-device-testing")
    assert res_testing.status_code == 200
    assert b"Coordinated Two-Device Testing System" in res_testing.data

    # Test API: token generation
    res_token = test_client.get("/api/devices/token/generate")
    assert res_token.status_code == 200
    assert "token" in res_token.get_json()

    # Test API: device registration
    reg_payload = {
        "device_id": "api-test-sender",
        "device_type": "sender",
        "hostname": "API-Sender-Node",
        "ip_address": "127.0.0.1",
        "os_info": "Linux x86_64"
    }
    res_reg = test_client.post("/api/devices/register", json=reg_payload)
    assert res_reg.status_code == 200
    data = res_reg.get_json()
    assert data["success"] is True

    # Test API: list devices
    res_list = test_client.get("/api/devices")
    assert res_list.status_code == 200
    assert res_list.get_json()["count"] >= 1

    # Test API: seed two-device demo
    res_seed = test_client.post("/api/two-device/demo/seed")
    assert res_seed.status_code == 200
    assert res_seed.get_json()["success"] is True
