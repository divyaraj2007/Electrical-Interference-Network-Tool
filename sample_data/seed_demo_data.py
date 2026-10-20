"""
Benchmark Test Data Generator.
Seeds realistic, rigorously labeled demonstration datasets into SQLite.
Explicitly flags datasets with is_demo=1 to ensure transparent scientific reporting.
"""

import sys
import os
import random
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import (
    init_db, create_session, start_session, end_session,
    record_ping_measurement, record_interface_stats,
    create_incident, record_comparative_test,
    record_packet_capture, record_analysis_result,
    DEFAULT_DB_PATH
)
from analysis.correlation import InvestigationCorrelationEngine


def seed_all_demo_data(db_path: str = DEFAULT_DB_PATH) -> int:
    """
    Seed a comprehensive benchmark dataset representing an industrial
    Variable Frequency Drive (VFD) interference investigation.
    """
    init_db(db_path)
    now = datetime.now()

    # 1. Create Demo Session
    session_id = create_session(
        name="[BENCHMARK] VFD Motor Interference & Cable Shielding Test",
        target="192.168.10.1",
        interval_sec=1.0,
        duration_sec=300,
        packet_count=120,
        timeout_sec=2.0,
        mode="multi_target",
        notes="BENCHMARK DEMONSTRATION DATASET: Simulates industrial VFD motor induction on Cat5e UTP vs Cat6a STP.",
        is_demo=1,
        db_path=db_path
    )
    start_session(session_id, db_path=db_path)

    # 2. Seed Ping Measurements (Baseline 40 pkts, Incident 40 pkts, Shielded 40 pkts)
    targets = [
        ("192.168.10.1", "gateway"),
        ("192.168.10.20", "local_peer"),
        ("8.8.8.8", "dns"),
        ("1.1.1.1", "internet")
    ]

    base_time = now - timedelta(minutes=15)
    seq = 0

    # Phase 1: Baseline Normal (Seq 1 - 40)
    for i in range(1, 41):
        seq += 1
        ts = (base_time + timedelta(seconds=seq)).strftime("%Y-%m-%d %H:%M:%S")
        rtt = round(random.uniform(0.8, 1.8), 2)
        record_ping_measurement(
            session_id=session_id,
            target="192.168.10.1",
            sequence_num=seq,
            rtt_ms=rtt,
            success=True,
            timeout=False,
            target_role="gateway",
            timestamp=ts,
            db_path=db_path
        )

    # Phase 2: VFD Active / Interference Burst (Seq 41 - 80)
    # Exhibits latency jitter, packet loss bursts, and timeouts
    for i in range(41, 81):
        seq += 1
        ts = (base_time + timedelta(seconds=seq)).strftime("%Y-%m-%d %H:%M:%S")
        is_drop = (i in [48, 49, 62, 63, 75])
        if is_drop:
            record_ping_measurement(
                session_id=session_id,
                target="192.168.10.1",
                sequence_num=seq,
                rtt_ms=None,
                success=False,
                timeout=True,
                error_msg="Request timed out (Frame dropped by switch)",
                target_role="gateway",
                timestamp=ts,
                db_path=db_path
            )
        else:
            spike_rtt = round(random.uniform(28.0, 94.5) if (i % 3 == 0) else random.uniform(1.5, 6.2), 2)
            record_ping_measurement(
                session_id=session_id,
                target="192.168.10.1",
                sequence_num=seq,
                rtt_ms=spike_rtt,
                success=True,
                timeout=False,
                target_role="gateway",
                timestamp=ts,
                db_path=db_path
            )

    # Phase 3: Cable Shielded / Rerouted Recovery (Seq 81 - 120)
    for i in range(81, 121):
        seq += 1
        ts = (base_time + timedelta(seconds=seq)).strftime("%Y-%m-%d %H:%M:%S")
        clean_rtt = round(random.uniform(0.7, 1.4), 2)
        record_ping_measurement(
            session_id=session_id,
            target="192.168.10.1",
            sequence_num=seq,
            rtt_ms=clean_rtt,
            success=True,
            timeout=False,
            target_role="gateway",
            timestamp=ts,
            db_path=db_path
        )

    # 3. Seed Interface Counter Snapshots with CRC/FCS Deltas
    record_interface_stats({
        "session_id": session_id,
        "interface_name": "Ethernet0 (Managed Switch Port 3)",
        "bytes_sent": 1420500,
        "bytes_recv": 5890200,
        "packets_sent": 8420,
        "packets_recv": 12450,
        "rx_errors": 18,
        "tx_errors": 0,
        "rx_drops": 12,
        "tx_drops": 0,
        "crc_fcs_errors": 18,
        "rx_errors_delta": 18,
        "tx_errors_delta": 0,
        "rx_drops_delta": 12,
        "crc_fcs_delta": 18,
        "link_speed_mbps": 1000,
        "is_up": True,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S")
    }, db_path=db_path)

    # 4. Create Incident Log
    incident_id = create_incident({
        "session_id": session_id,
        "title": "Industrial CNC Mill / VFD Induction along Overhead Cable Tray",
        "location": "Manufacturing Facility Building B - Production Line 2",
        "equipment_involved": "Allen-Bradley PowerFlex 525 VFD & 15kW 3-Phase Spindle Motor",
        "cable_type": "Cat5e UTP (Unshielded, ungrounded)",
        "cable_length_m": 28.5,
        "distance_to_source_m": 0.12,  # 12 cm separation (Violates TIA-568)
        "equipment_operating": True,
        "electrical_source_type": "vfd",
        "baseline_latency": 1.25,
        "incident_latency": 42.80,
        "baseline_loss": 0.0,
        "incident_loss": 12.5,
        "crc_fcs_observed": 18,
        "isolation_test_result": "Separating cable by 40 cm or replacing with Cat6a STP eliminated packet loss.",
        "investigator_notes": (
            "Observed unshielded Cat5e horizontal run routed in immediate proximity to 480V 3-phase VFD output conduit. "
            "Severe packet drops and switch FCS increments coincided with motor ramp-up. "
            "Rerouting outside conduit zone immediately normalized throughput."
        )
    }, db_path=db_path)

    # 5. Record Comparative Tests (A, B, C, D)
    tests = [
        {
            "incident_id": incident_id,
            "test_code": "A",
            "title": "Normal Baseline (VFD Inactive)",
            "description": "Spindle motor powered off; ambient plant background noise only.",
            "duration_sec": 60,
            "avg_rtt": 1.18,
            "min_rtt": 0.82,
            "max_rtt": 1.95,
            "packet_loss_pct": 0.0,
            "crc_error_delta": 0,
            "packets_transmitted": 60,
            "packets_received": 60,
            "observations": "Zero packet loss. Latency completely flat under 2 ms."
        },
        {
            "incident_id": incident_id,
            "test_code": "B",
            "title": "Suspected EMI Active (VFD Running at 60Hz)",
            "description": "Spindle motor operational at 12,000 RPM under load; unshielded cable in place.",
            "duration_sec": 60,
            "avg_rtt": 38.45,
            "min_rtt": 1.20,
            "max_rtt": 94.50,
            "packet_loss_pct": 8.33,
            "crc_error_delta": 18,
            "packets_transmitted": 60,
            "packets_received": 55,
            "observations": "Bursts of packet loss coinciding with VFD PWM switching. Switch logged 18 FCS corruptions."
        },
        {
            "incident_id": incident_id,
            "test_code": "C",
            "title": "Cable Safely Rerouted (45 cm Separation)",
            "description": "Same Cat5e cable rerouted outside electrical tray to maintain 450 mm clearance.",
            "duration_sec": 60,
            "avg_rtt": 1.35,
            "min_rtt": 0.90,
            "max_rtt": 2.40,
            "packet_loss_pct": 0.0,
            "crc_error_delta": 0,
            "packets_transmitted": 60,
            "packets_received": 60,
            "observations": "Physical distance separation eliminated induced noise. Zero CRC errors."
        },
        {
            "incident_id": incident_id,
            "test_code": "D",
            "title": "Shielded Cable Test (Cat6a S/FTP with Grounding)",
            "description": "Installed industrial Cat6a foil/braid shielded cable with metal-shielded RJ45 jacks.",
            "duration_sec": 60,
            "avg_rtt": 1.12,
            "min_rtt": 0.78,
            "max_rtt": 1.65,
            "packet_loss_pct": 0.0,
            "crc_error_delta": 0,
            "packets_transmitted": 60,
            "packets_received": 60,
            "observations": "Complete immunity to electromagnetic induction even when routed adjacent to conduit."
        }
    ]

    for t in tests:
        record_comparative_test(t, db_path=db_path)

    # 6. Record Packet Capture Metadata
    record_packet_capture({
        "session_id": session_id,
        "filename": "vfd_interference_capture_demo.pcapng",
        "filepath": os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "captures", "demo.pcapng"),
        "interface_name": "Ethernet0",
        "duration_sec": 120.0,
        "packet_count": 4820,
        "file_size_bytes": 1048576,
        "tcp_retransmissions": 42,
        "dup_acks": 31,
        "dns_failures": 0,
        "tcp_resets": 3,
        "protocol_summary": {"TCP": 3820, "UDP": 640, "ICMP": 240, "ARP": 120},
        "analysis_notes": (
            "High rate of TCP fast retransmissions and selective ACKs matching the exact "
            "timing of switch FCS error burst discards."
        )
    }, db_path=db_path)

    # 7. Run Correlation Engine on this Benchmark Dataset
    engine = InvestigationCorrelationEngine()
    diag = engine.analyze_investigation(
        baseline_pings=[{"rtt_ms": 1.2, "success": True, "timeout": False}] * 40,
        incident_pings=[{"rtt_ms": 38.5, "success": True, "timeout": False}] * 35 + [{"rtt_ms": None, "success": False, "timeout": True}] * 5,
        comparative_tests=tests,
        interface_stats_deltas={"crc_fcs_delta": 18, "rx_errors_delta": 18, "rx_drops_delta": 12},
        incident_meta={"equipment_operating": True, "cable_type": "Cat5e UTP"},
        packet_capture_meta={"tcp_retransmissions": 42, "dup_acks": 31}
    )

    record_analysis_result({
        "session_id": session_id,
        "incident_id": incident_id,
        "category": diag.category.value,
        "confidence_score": diag.confidence_score,
        "rtt_baseline_avg": 1.2,
        "rtt_incident_avg": 38.5,
        "rtt_delta_pct": 3108.3,
        "loss_baseline_pct": 0.0,
        "loss_incident_pct": 12.5,
        "crc_fcs_total_delta": 18,
        "findings": diag.detailed_findings,
        "recommendations": diag.remediation_recommendations
    }, db_path=db_path)

    end_session(session_id, status="completed", db_path=db_path)
    logger.info("Successfully seeded benchmark demonstration session %d.", session_id)
    return session_id


if __name__ == "__main__":
    sid = seed_all_demo_data()
    print(f"Successfully initialized and seeded benchmark demonstration dataset (Session ID: {sid}).")
