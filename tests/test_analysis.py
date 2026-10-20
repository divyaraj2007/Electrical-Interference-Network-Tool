"""
Unit Tests for Network Statistical Analysis & Root-Cause Correlation Engine.
"""

import pytest
import math
from analysis.network_analysis import calculate_statistics, detect_latency_spikes, compare_periods
from analysis.correlation import InvestigationCorrelationEngine, DiagnosticCategory


def test_calculate_statistics_nominal():
    """Verify statistical metrics on a known dataset."""
    rtts = [10.0, 12.0, 14.0, 16.0, 18.0]
    stats = calculate_statistics(rtts)
    assert stats["count"] == 5
    assert stats["mean"] == 14.0
    assert stats["median"] == 14.0
    assert stats["min"] == 10.0
    assert stats["max"] == 18.0
    assert stats["std_dev"] > 0
    assert stats["jitter"] == 2.0


def test_calculate_statistics_empty():
    """Verify empty input handling."""
    stats = calculate_statistics([])
    assert stats["count"] == 0
    assert stats["mean"] == 0.0
    assert stats["min"] == 0.0
    assert stats["max"] == 0.0


def test_detect_latency_spikes():
    """Verify detection of outliers beyond statistical threshold."""
    measurements = [
        {"sequence_num": 1, "rtt_ms": 1.2},
        {"sequence_num": 2, "rtt_ms": 1.3},
        {"sequence_num": 3, "rtt_ms": 1.1},
        {"sequence_num": 4, "rtt_ms": 1.4},
        {"sequence_num": 5, "rtt_ms": 1.2},
        {"sequence_num": 6, "rtt_ms": 85.0}, # Outlier Spike
        {"sequence_num": 7, "rtt_ms": 1.3}
    ]
    spikes = detect_latency_spikes(measurements, std_dev_multiplier=2.0, absolute_min_spike_ms=20.0)
    assert len(spikes) == 1
    assert spikes[0]["sequence_num"] == 6
    assert spikes[0]["rtt_ms"] == 85.0


def test_compare_periods_degradation():
    """Verify baseline vs incident period comparison."""
    baseline = [{"rtt_ms": 1.5, "success": True, "timeout": False}] * 20
    incident = [{"rtt_ms": 45.0, "success": True, "timeout": False}] * 18 + [{"rtt_ms": None, "success": False, "timeout": True}] * 2

    comp = compare_periods(baseline, incident, error_counter_delta=5)
    assert comp["deltas"]["rtt_mean_delta_ms"] > 40.0
    assert comp["incident"]["loss_pct"] == 10.0
    assert comp["flags"]["latency_degraded"] is True
    assert comp["flags"]["loss_degraded"] is True
    assert comp["flags"]["interface_errors_present"] is True


def test_correlation_insufficient_data():
    """Verify rule: less than 20 measurements yields insufficient evidence."""
    engine = InvestigationCorrelationEngine()
    diag = engine.analyze_investigation(
        baseline_pings=[{"rtt_ms": 2.0, "success": True}] * 5,
        incident_pings=[{"rtt_ms": 50.0, "success": True}] * 5
    )
    assert diag.category == DiagnosticCategory.INSUFFICIENT_EVIDENCE
    assert diag.confidence_score <= 30.0


def test_correlation_physical_layer_crc_delta():
    """Verify rule: hardware CRC/FCS counter increments point to physical layer."""
    engine = InvestigationCorrelationEngine()
    baseline = [{"rtt_ms": 1.2, "success": True, "timeout": False}] * 30
    incident = [{"rtt_ms": 35.0, "success": True, "timeout": False}] * 25 + [{"rtt_ms": None, "success": False, "timeout": True}] * 5

    diag = engine.analyze_investigation(
        baseline_pings=baseline,
        incident_pings=incident,
        interface_stats_deltas={"crc_fcs_delta": 14, "rx_errors_delta": 14}
    )
    assert diag.category == DiagnosticCategory.PHYSICAL_LAYER_POSSIBLE_EMI
    assert diag.confidence_score >= 50.0


def test_correlation_hop_isolation_routing():
    """Verify rule: if hop 1 (gateway) is clean but remote hop fails -> Upstream Routing."""
    engine = InvestigationCorrelationEngine()
    baseline = [{"rtt_ms": 1.2, "success": True}] * 25
    incident = [{"rtt_ms": 65.0, "success": True}] * 20 + [{"rtt_ms": None, "success": False}] * 5

    multi_targets = {
        "gateway": [{"rtt_ms": 1.1, "success": True}] * 25, # Clean local drop
        "remote": [{"rtt_ms": 85.0, "success": True}] * 20 + [{"rtt_ms": None, "success": False}] * 5 # Degraded remote
    }

    diag = engine.analyze_investigation(
        baseline_pings=baseline,
        incident_pings=incident,
        multi_target_pings=multi_targets
    )
    assert diag.category == DiagnosticCategory.ROUTING_OR_GATEWAY
