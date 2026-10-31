"""
Security, Authentication, and Input Validation Module for Device Testing Agents.
Guards against shell injection, parameter tampering, and unauthorized execution.
Only permits validated, whitelisted network testing actions.
"""

import os
import re
import ssl
import secrets
import ipaddress
import logging
from typing import Optional, Dict, Any, Union

logger = logging.getLogger("agent.security")

# Permitted hostname regex (RFC 1123 compliant)
HOSTNAME_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
# Interface name sanitization regex (alphanumeric, dashes, underscores, dots, colons, spaces)
SAFE_INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9\-_.: ]{1,64}$")
# Device ID regex
DEVICE_ID_REGEX = re.compile(r"^[a-zA-Z0-9\-_]{3,64}$")


def generate_device_token(length: int = 32) -> str:
    """Generate a cryptographically secure random API token for agent authentication."""
    return secrets.token_hex(length)


def validate_device_id(device_id: str) -> str:
    """Validate and sanitize a device ID string."""
    if not device_id or not isinstance(device_id, str):
        raise ValueError("Device ID cannot be empty.")
    clean_id = device_id.strip()
    if not DEVICE_ID_REGEX.match(clean_id):
        raise ValueError(f"Invalid device ID '{clean_id}'. Must be 3-64 alphanumeric characters, dashes, or underscores.")
    return clean_id


def validate_ip_or_hostname(target: str) -> str:
    """
    Validate target string as either a valid IPv4/IPv6 address or a safe RFC 1123 hostname.
    Strictly forbids command injection characters (; & | ` $ > < \n \r).
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target host cannot be empty.")
    
    clean_target = target.strip()

    # Reject dangerous shell characters explicitly
    for bad_char in [";", "&", "|", "`", "$", ">", "<", "\n", "\r", '"', "'", "(", ")", "{", "}"]:
        if bad_char in clean_target:
            raise ValueError(f"Target contains forbidden character '{bad_char}'. Possible injection attempt.")

    # Check if valid IP
    try:
        ipaddress.ip_address(clean_target)
        return clean_target
    except ValueError:
        pass

    # Check if valid hostname
    if HOSTNAME_REGEX.match(clean_target) and len(clean_target) <= 253:
        return clean_target

    raise ValueError(f"Target '{clean_target}' is neither a valid IP address nor an allowed hostname.")


def validate_port(port: Union[int, str], default: int = 5201) -> int:
    """Validate TCP/UDP port number (1-65535)."""
    try:
        p = int(port)
        if 1 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    raise ValueError(f"Invalid network port '{port}'. Must be an integer between 1 and 65535.")


def validate_packet_size(size: Union[int, str], min_size: int = 32, max_size: int = 65507) -> int:
    """Validate network packet payload size in bytes."""
    try:
        s = int(size)
        if min_size <= s <= max_size:
            return s
    except (ValueError, TypeError):
        pass
    raise ValueError(f"Invalid packet size '{size}'. Allowed range: {min_size}-{max_size} bytes.")


def validate_duration(duration_sec: Union[int, float, str], min_dur: int = 1, max_dur: int = 86400) -> int:
    """Validate test duration in seconds."""
    try:
        d = int(duration_sec)
        if min_dur <= d <= max_dur:
            return d
    except (ValueError, TypeError):
        pass
    raise ValueError(f"Invalid duration '{duration_sec}'. Allowed range: {min_dur}-{max_dur} seconds.")


def validate_interval(interval_sec: Union[int, float, str], min_int: float = 0.05, max_int: float = 60.0) -> float:
    """Validate interval in seconds between packets/probes."""
    try:
        i = float(interval_sec)
        if min_int <= i <= max_int:
            return round(i, 3)
    except (ValueError, TypeError):
        pass
    raise ValueError(f"Invalid interval '{interval_sec}'. Allowed range: {min_int}-{max_int} seconds.")


def validate_interface_name(name: Optional[str]) -> str:
    """Validate and sanitize network interface identifier."""
    if not name:
        return ""
    clean = name.strip()
    if not SAFE_INTERFACE_REGEX.match(clean):
        raise ValueError(f"Invalid interface name '{clean}'.")
    return clean


def create_ssl_context(verify_ssl: bool = True, ca_cert_path: Optional[str] = None) -> ssl.SSLContext:
    """
    Construct safe SSL context for HTTPS requests.
    Allows self-signed development certificates only when verify_ssl is explicitly False.
    """
    if verify_ssl:
        if ca_cert_path and os.path.exists(ca_cert_path):
            ctx = ssl.create_default_context(cafile=ca_cert_path)
        else:
            ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
