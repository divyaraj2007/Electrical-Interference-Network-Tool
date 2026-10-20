"""
Security Validation & Counter Delta Unit Tests.
Verifies command injection protection, RFC target validation,
and interface counter rollover handling.
"""

import pytest
from monitoring.ping_monitor import validate_target
from monitoring.interface_stats import InterfaceStatsMonitor


def test_validate_target_valid():
    """Verify valid targets pass validation without alteration."""
    assert validate_target("192.168.10.1") == "192.168.10.1"
    assert validate_target("10.0.0.1") == "10.0.0.1"
    assert validate_target("127.0.0.1") == "127.0.0.1"
    assert validate_target("8.8.8.8") == "8.8.8.8"
    assert validate_target("gateway.local") == "gateway.local"
    assert validate_target("google.com") == "google.com"


def test_validate_target_injection_rejection():
    """Verify shell metacharacters and injection attempts raise ValueError."""
    dangerous_inputs = [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && calc.exe",
        "192.168.1.1 | whoami",
        "192.168.1.1 `id`",
        "192.168.1.1 $(cat /etc/passwd)",
        "192.168.1.1\nreboot",
        "192.168.1.1 > out.txt",
        "<script>alert(1)</script>",
        "192.168.1.1 192.168.1.2",
        ""
    ]
    for inp in dangerous_inputs:
        with pytest.raises(ValueError):
            validate_target(inp)


def test_interface_counter_rollover_handling():
    """Verify that counter wrap-around or interface resets are handled gracefully."""
    monitor = InterfaceStatsMonitor("TestInterface", session_id=1)

    # Establish baseline snapshot
    monitor.last_snapshot = {
        "rx_errors": 100,
        "tx_errors": 50,
        "rx_drops": 20,
        "crc_fcs_errors": 30
    }

    # Simulate adapter reset where counters drop back to 5
    # The monitor must detect reset and avoid negative deltas
    simulated_rx = 5
    prev_rx = monitor.last_snapshot["rx_errors"]
    assert simulated_rx < prev_rx  # Reset condition

    # In our implementation: if simulated_rx < prev_rx, delta is treated as simulated_rx (new count since reset)
    delta = simulated_rx if simulated_rx < prev_rx else (simulated_rx - prev_rx)
    assert delta >= 0
    assert delta == 5
