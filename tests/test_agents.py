"""
Unit tests for Device Agent Architecture and Common Modules.
Validates input sanitization, security controls, system telemetry,
jitter calculation, and pure-Python socket fallback.
"""

import sys
import os
import pytest
import socket
import time

# Ensure agents and parent paths are included
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.common.security import (
    validate_device_id, validate_ip_or_hostname, validate_port,
    validate_packet_size, validate_duration, validate_interval,
    validate_interface_name, generate_device_token
)
from agents.common.ping_monitor import calculate_rfc3550_jitter
from agents.common.system_info import get_operating_system_info, get_interfaces_detail
from agents.common.iperf_manager import FallbackSocketServer, run_fallback_socket_client
from agents.common.dns_test import test_dns_resolution as run_dns_test


def test_device_token_generation():
    """Verify cryptographically secure token generation."""
    token1 = generate_device_token()
    token2 = generate_device_token()
    assert isinstance(token1, str)
    assert len(token1) == 64  # 32 bytes hex
    assert token1 != token2


def test_device_id_validation():
    """Verify device ID sanitization and validation."""
    assert validate_device_id("sender-node-01") == "sender-node-01"
    assert validate_device_id("receiver_test_123") == "receiver_test_123"

    with pytest.raises(ValueError):
        validate_device_id("ab")  # Too short (< 3 chars)

    with pytest.raises(ValueError):
        validate_device_id("sender;rm -rf /")  # Dangerous characters


def test_target_security_sanitization():
    """Verify IP and hostname validation prevents shell injection."""
    assert validate_ip_or_hostname("192.168.1.1") == "192.168.1.1"
    assert validate_ip_or_hostname("8.8.8.8") == "8.8.8.8"
    assert validate_ip_or_hostname("localhost") == "localhost"
    assert validate_ip_or_hostname("subdomain.example.com") == "subdomain.example.com"

    # Test rejection of command injection characters
    injection_targets = [
        "192.168.1.1; whoami",
        "192.168.1.1 | cat /etc/passwd",
        "127.0.0.1 && echo hack",
        "`ping google.com`",
        "$(reboot)",
        "192.168.1.1\nreboot",
        "192.168.1.1 > out.txt"
    ]
    for bad_target in injection_targets:
        with pytest.raises(ValueError):
            validate_ip_or_hostname(bad_target)


def test_parameter_bounds_validation():
    """Verify port, packet size, duration, and interval bounds."""
    assert validate_port(80) == 80
    assert validate_port("5201") == 5201
    with pytest.raises(ValueError):
        validate_port(70000)

    assert validate_packet_size(64) == 64
    assert validate_packet_size(1500) == 1500
    with pytest.raises(ValueError):
        validate_packet_size(10)  # Too small

    assert validate_duration(30) == 30
    with pytest.raises(ValueError):
        validate_duration(0)

    assert validate_interval(0.5) == 0.5
    with pytest.raises(ValueError):
        validate_interval(0.001)  # Below 0.05s limit


def test_rfc3550_jitter_calculation():
    """Verify RFC 3550 interarrival jitter calculation algorithm."""
    # Constant delay should yield 0 jitter
    samples_flat = [10.0, 10.0, 10.0, 10.0, 10.0]
    assert calculate_rfc3550_jitter(samples_flat) == 0.0

    # Fluctuating delay
    samples_varying = [10.0, 26.0, 10.0, 26.0, 10.0]
    jitter = calculate_rfc3550_jitter(samples_varying)
    assert jitter > 0.0
    assert isinstance(jitter, float)


def test_system_info_collection():
    """Verify operating system and interface metadata retrieval."""
    os_info = get_operating_system_info()
    assert "os_name" in os_info
    assert "hostname" in os_info
    assert len(os_info["hostname"]) > 0

    interfaces = get_interfaces_detail()
    assert isinstance(interfaces, list)
    if interfaces:
        first = interfaces[0]
        assert "name" in first
        assert "is_up" in first
        assert "speed_mbps" in first
        assert "crc_supported" in first
        assert "crc_display" in first


def test_fallback_socket_throughput():
    """Verify built-in pure-Python fallback throughput server and client."""
    # Find free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    free_port = sock.getsockname()[1]
    sock.close()

    server = FallbackSocketServer(port=free_port)
    server.start()
    time.sleep(0.3)

    try:
        # Run 1-second local stream test
        client_res = run_fallback_socket_client("127.0.0.1", port=free_port, duration_sec=1)
        assert client_res["success"] is True
        assert client_res["throughput_mbps"] > 0.0
        assert client_res["bytes_transferred"] > 0
    finally:
        server.stop()


def test_dns_resolution_execution():
    """Verify DNS resolution test execution."""
    res = run_dns_test("localhost")
    assert "hostname" in res
    assert "latency_ms" in res
    assert isinstance(res["latency_ms"], float)
