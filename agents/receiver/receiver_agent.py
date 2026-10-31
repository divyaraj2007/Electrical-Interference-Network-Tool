"""
Device 2 – Receiver Network Testing Agent.
Runs on Windows 10/11, Ubuntu, Kali, and other Linux distributions.
Maintains iperf3 / socket server, monitors incoming traffic, records physical
interface error counters, and transmits receiver telemetry to the Flask server.
"""

import sys
import os
import json
import time
import signal
import logging
import argparse
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Ensure parent directory is in sys.path to import common modules
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENTS_DIR = os.path.dirname(CURRENT_DIR)
if AGENTS_DIR not in sys.path:
    sys.path.insert(0, AGENTS_DIR)

from common.security import validate_device_id, validate_ip_or_hostname
from common.system_info import (
    get_operating_system_info, get_system_resource_usage,
    get_interfaces_detail, get_primary_interface
)
from common.interface_monitor import AgentInterfaceMonitor
from common.iperf_manager import IperfServerDaemon
from common.network_tests import NetworkTestOrchestrator
from common.agent_communication import AgentCommunicator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RECEIVER-%(levelname)s] %(message)s"
)
logger = logging.getLogger("ReceiverAgent")


class ReceiverAgent:
    """Device 2 Receiver Agent Service."""

    def __init__(self, config_path: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None):
        self.config = self._load_config(config_path, overrides)
        self.device_id = self.config["device_id"]
        self.auth_token = self.config["auth_token"]
        self.server_url = self.config["server_url"]
        self.interface_name = self.config.get("interface_name")
        self.iperf_port = int(self.config.get("iperf_port", 5201))
        self.heartbeat_interval = float(self.config.get("heartbeat_interval_sec", 3.0))

        self.communicator = AgentCommunicator(
            server_url=self.server_url,
            device_id=self.device_id,
            auth_token=self.auth_token,
            verify_ssl=bool(self.config.get("verify_ssl", False))
        )

        self.interface_monitor = AgentInterfaceMonitor(interface_name=self.interface_name)
        self.server_daemon = IperfServerDaemon(port=self.iperf_port)
        self.orchestrator = NetworkTestOrchestrator(interface_name=self.interface_name)

        self.running = False
        self.active_test_thread: Optional[threading.Thread] = None

    def _load_config(self, config_path: Optional[str], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        cfg = {
            "server_url": "http://127.0.0.1:5000",
            "device_id": "receiver-node-02",
            "device_name": "Device 2 – Primary Receiver",
            "device_type": "receiver",
            "auth_token": "receiver-auth-token-secret-key-67890",
            "interface_name": "",
            "heartbeat_interval_sec": 3.0,
            "verify_ssl": False,
            "iperf_port": 5201,
            "agent_version": "1.1.0"
        }

        path = config_path or os.path.join(CURRENT_DIR, "receiver_config.json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
                    cfg.update(file_cfg)
            except Exception as e:
                logger.warning("Could not read receiver config file: %s", e)

        if overrides:
            for k, v in overrides.items():
                if v is not None:
                    cfg[k] = v

        return cfg

    def start(self):
        """Start the Receiver Agent and initialize server daemon."""
        self.running = True
        logger.info("Initializing Receiver Agent (Device ID: %s)...", self.device_id)

        # 1. Start iperf3 / socket throughput server daemon
        srv_status = self.server_daemon.start()
        logger.info("Throughput server status: %s", srv_status)

        # 2. Register device with central server
        os_info = get_operating_system_info()
        interfaces = get_interfaces_detail()
        primary_if = get_primary_interface()

        meta = {
            "device_type": "receiver",
            "hostname": os_info["hostname"],
            "ip_address": primary_if["ipv4"] if primary_if else "127.0.0.1",
            "os_info": f"{os_info['distro_name']} ({os_info['architecture']})",
            "interfaces_json": interfaces,
            "agent_version": self.config.get("agent_version", "1.1.0"),
            "active_interface": primary_if["name"] if primary_if else "",
            "link_speed_mbps": primary_if["speed_mbps"] if primary_if else 0,
            "config_json": self.config
        }

        while self.running:
            if self.communicator.register_device(meta):
                logger.info("Receiver successfully registered with Flask server.")
                break
            logger.warning("Registration failed. Server may be down. Retrying...")
            self.communicator.handle_reconnect_sleep()

        # 3. Launch background heartbeat daemon
        hb_thread = threading.Thread(target=self._heartbeat_loop, name="ReceiverHeartbeat", daemon=True)
        hb_thread.start()

        # 4. Main task polling loop
        logger.info("Receiver Agent online, listening on port %d, and polling for tasks.", self.iperf_port)
        try:
            while self.running:
                tasks = self.communicator.fetch_pending_tasks()
                for task in tasks:
                    self._handle_task(task)
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal. Shutting down Receiver Agent...")
        finally:
            self.stop()

    def _heartbeat_loop(self):
        """Send periodic telemetry heartbeats to Flask server."""
        while self.running:
            try:
                res = get_system_resource_usage()
                snap = self.interface_monitor.capture_snapshot()
                telemetry = {
                    "cpu_pct": res["cpu_pct"],
                    "mem_pct": res["mem_pct"],
                    "active_interface": snap["interface_name"],
                    "link_speed_mbps": snap["link_speed_mbps"],
                    "rx_errors": snap["rx_errors"],
                    "tx_errors": snap["tx_errors"],
                    "rx_drops": snap["rx_drops"],
                    "tx_drops": snap["tx_drops"],
                    "crc_fcs_errors": snap["crc_fcs_errors"] if snap["crc_supported"] else 0,
                    "crc_supported": 1 if snap["crc_supported"] else 0
                }
                self.communicator.send_heartbeat(telemetry)
            except Exception as e:
                logger.debug("Heartbeat exception: %s", e)

            time.sleep(self.heartbeat_interval)

    def _handle_task(self, task: Dict[str, Any]):
        """Handle tasks assigned to the Receiver."""
        task_type = task.get("task_type")
        task_id = task.get("task_id")
        payload = task.get("payload", {})

        logger.info("Receiver received task: %s (ID: %s)", task_type, task_id)

        if task_type == "run_test":
            # For reverse direction (receiver_to_sender), Receiver acts as client!
            # Otherwise, Receiver captures its local interface statistics throughout the test duration.
            self.active_test_thread = threading.Thread(
                target=self._execute_receiver_test_task,
                args=(task_id, payload),
                daemon=True
            )
            self.active_test_thread.start()

        elif task_type == "restart_server":
            self.server_daemon.stop()
            res = self.server_daemon.start()
            self.communicator.report_task_result(task_id, "completed", res)

    def _execute_receiver_test_task(self, task_id: str, payload: Dict[str, Any]):
        """Execute receiver-side test monitoring or reverse-direction client test."""
        direction = payload.get("direction", "sender_to_receiver")
        duration = int(payload.get("duration_sec", 15))
        sender_ip = payload.get("sender_ip", "127.0.0.1")
        test_modes = payload.get("test_modes", ["icmp_ping", "rtt", "jitter", "loss", "tcp_throughput"])

        utc_start = datetime.now(timezone.utc).isoformat()
        snap_initial = self.interface_monitor.capture_snapshot()

        if direction == "receiver_to_sender":
            # Receiver acts as active client towards Sender
            logger.info("Executing reverse-direction test from Receiver to Sender %s", sender_ip)
            try:
                results = self.orchestrator.execute_test_suite(
                    target_ip=sender_ip,
                    test_modes=test_modes,
                    duration_sec=duration,
                    packet_size=int(payload.get("packet_size_bytes", 64)),
                    interval_sec=float(payload.get("interval_sec", 0.5)),
                    direction="receiver_to_sender",
                    iperf_port=self.iperf_port,
                    role="receiver"
                )
                self.communicator.report_task_result(task_id, "completed", results)
                return
            except Exception as e:
                logger.error("Reverse test failed: %s", e)
                self.communicator.report_task_result(task_id, "failed", {"error": str(e)})
                return

        # Forward direction: Monitor incoming traffic and record metrics during test window
        logger.info("Monitoring receiver interface for %d seconds during test %s...", duration, task_id)
        time.sleep(duration + 1.0)
        snap_final = self.interface_monitor.capture_snapshot()
        utc_end = datetime.now(timezone.utc).isoformat()

        bytes_received = max(0, snap_final["bytes_recv"] - snap_initial["bytes_recv"])
        packets_received = max(0, snap_final["packets_recv"] - snap_initial["packets_recv"])
        rx_mbps = round((bytes_received * 8.0) / (duration * 1_000_000.0), 2) if duration > 0 else 0.0

        receiver_results = {
            "target": sender_ip,
            "role": "receiver",
            "direction": direction,
            "duration_sec": duration,
            "start_time_utc": utc_start,
            "end_time_utc": utc_end,
            "interface_initial": snap_initial,
            "interface_final": snap_final,
            "interface_deltas": {
                "rx_errors_delta": snap_final["rx_errors_delta"],
                "tx_errors_delta": snap_final["tx_errors_delta"],
                "rx_drops_delta": snap_final["rx_drops_delta"],
                "tx_drops_delta": snap_final["tx_drops_delta"],
                "crc_delta": snap_final["crc_delta"],
                "crc_supported": snap_final["crc_supported"],
                "crc_display": snap_final["crc_display"],
                "reset_detected": snap_final["reset_detected"]
            },
            "incoming_traffic": {
                "bytes_received": bytes_received,
                "packets_received": packets_received,
                "measured_throughput_mbps": rx_mbps
            }
        }

        self.communicator.report_task_result(task_id, "completed", receiver_results)
        logger.info("Receiver test task %s completed and posted to server.", task_id)

    def stop(self):
        """Stop agent and terminate iperf daemon."""
        self.running = False
        self.server_daemon.stop()
        logger.info("Receiver Agent terminated.")


def parse_args():
    parser = argparse.ArgumentParser(description="Receiver Network Testing Agent (Device 2)")
    parser.add_argument("--server", type=str, help="Flask central server URL (e.g. http://192.168.1.50:5000)")
    parser.add_argument("--id", type=str, help="Device ID")
    parser.add_argument("--token", type=str, help="Authentication API Token")
    parser.add_argument("--interface", type=str, help="Network interface name to monitor")
    parser.add_argument("--port", type=int, help="iperf3 / socket listening port")
    parser.add_argument("--config", type=str, help="Path to receiver_config.json")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    overrides = {
        "server_url": args.server,
        "device_id": args.id,
        "auth_token": args.token,
        "interface_name": args.interface,
        "iperf_port": args.port
    }
    agent = ReceiverAgent(config_path=args.config, overrides=overrides)
    agent.start()
