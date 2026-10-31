"""
Robust HTTP/HTTPS Client for Agent-to-Server Communication.
Handles authentication headers, heartbeats, task polling, and automatic reconnection.
Uses Python's standard urllib to guarantee zero external package dependencies.
"""

import sys
import json
import time
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from .security import create_ssl_context

logger = logging.getLogger("agent.comm")


class AgentCommunicator:
    """Manages connection, heartbeats, and data transfer with the central Flask dashboard."""

    def __init__(self,
                 server_url: str,
                 device_id: str,
                 auth_token: str,
                 verify_ssl: bool = False,
                 ca_cert_path: Optional[str] = None):
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id
        self.auth_token = auth_token
        self.ssl_context = create_ssl_context(verify_ssl=verify_ssl, ca_cert_path=ca_cert_path)
        self.is_connected = False
        self.backoff_sec = 2.0
        self.max_backoff_sec = 30.0

    def _make_request(self, endpoint: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        """Execute HTTP request with token authentication header."""
        url = f"{self.server_url}{endpoint}"
        body = json.dumps(data).encode("utf-8") if data is not None else None

        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Device-Token", self.auth_token)
        req.add_header("X-Device-ID", self.device_id)

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
                self.is_connected = True
                self.backoff_sec = 2.0  # Reset backoff on success
                if raw:
                    return json.loads(raw)
                return {}
        except urllib.error.HTTPError as he:
            logger.error("HTTP error %d accessing %s: %s", he.code, endpoint, he.reason)
            return None
        except urllib.error.URLError as ue:
            logger.warning("Connection failure to server %s: %s. Reconnecting in %.1fs...", self.server_url, ue.reason, self.backoff_sec)
            self.is_connected = False
            return None
        except Exception as e:
            logger.error("Unexpected network error: %s", e)
            self.is_connected = False
            return None

    def register_device(self, metadata: Dict[str, Any]) -> bool:
        """Register device with the central server."""
        payload = {
            "device_id": self.device_id,
            "auth_token": self.auth_token,
            **metadata
        }
        res = self._make_request("/api/devices/register", method="POST", data=payload)
        if res and res.get("success"):
            logger.info("Device %s successfully registered with server %s", self.device_id, self.server_url)
            self.is_connected = True
            return True
        return False

    def send_heartbeat(self, telemetry: Dict[str, Any]) -> bool:
        """Send periodic heartbeat to server."""
        payload = {
            "device_id": self.device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **telemetry
        }
        res = self._make_request("/api/devices/heartbeat", method="POST", data=payload, timeout=5.0)
        return bool(res and res.get("success"))

    def fetch_pending_tasks(self) -> list:
        """Query server for queued tasks."""
        res = self._make_request(f"/api/devices/{self.device_id}/tasks", method="GET", timeout=5.0)
        if res and isinstance(res, dict):
            return res.get("tasks", [])
        return []

    def report_task_result(self, task_id: str, status: str, result: Dict[str, Any]) -> bool:
        """Post completed task diagnostics to server."""
        payload = {
            "device_id": self.device_id,
            "task_id": task_id,
            "status": status,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        res = self._make_request(f"/api/devices/{self.device_id}/results", method="POST", data=payload)
        return bool(res and res.get("success"))

    def post_telemetry_stream(self, metric_data: Dict[str, Any]) -> bool:
        """Stream real-time metric point to server."""
        payload = {
            "device_id": self.device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **metric_data
        }
        res = self._make_request(f"/api/devices/{self.device_id}/telemetry", method="POST", data=payload, timeout=3.0)
        return bool(res and res.get("success"))

    def handle_reconnect_sleep(self):
        """Sleep with exponential backoff when disconnected."""
        time.sleep(self.backoff_sec)
        self.backoff_sec = min(self.max_backoff_sec, self.backoff_sec * 1.5)
