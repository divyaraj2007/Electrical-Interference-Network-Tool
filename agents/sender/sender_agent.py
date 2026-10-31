"""
Device 1 – Sender Network Testing Agent.
Runs on Windows 10/11, Ubuntu, Kali, and other Linux distributions.
Communicates with the central Flask dashboard, maintains heartbeat,
and executes coordinated sender-side network diagnostics.
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
from common.network_tests import NetworkTestOrchestrator
from common.agent_communication import AgentCommunicator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENDER-%(levelname)s] %(message)s"
)
logger = logging.getLogger("SenderAgent")


class SenderAgent:
    """Device 1 Sender Agent Service."""

    def __init__(self, config_path: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None):
        self.config = self._load_config(config_path, overrides)
        self.device_id = self.config["device_id"]
        self.auth_token = self.config["auth_token"]
        self.server_url = self.config["server_url"]
        self.interface_name = self.config.get("interface_name")
        self.heartbeat_interval = float(self.config.get("heartbeat_interval_sec", 3.0))

        self.communicator = AgentCommunicator(
            server_url=self.server_url,
            device_id=self.device_id,
            auth_token=self.auth_token,
            verify_ssl=bool(self.config.get("verify_ssl", False))
        )

        self.interface_monitor = AgentInterfaceMonitor(interface_name=self.interface_name)
        self.orchestrator = NetworkTestOrchestrator(interface_name=self.interface_name)

        self.running = False
        self.active_test_thread: Optional[threading.Thread] = None

    def _load_config(self, config_path: Optional[str], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        cfg = {
            "server_url": "http://127.0.0.1:5000",
            "device_id": "sender-node-01",
            "device_name": "Device 1 - Primary Sender",
            "device_type": "sender",
            "auth_token": "sender-auth-token-secret-key-12345",
            "interface_name": "",
            "heartbeat_interval_sec": 3.0,
            "verify_ssl": False,
            "iperf_port": 5201,
            "agent_version": "1.1.0"
        }

        path = config_path or os.path.join(CURRENT_DIR, "sender_config.json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
                    cfg.update(file_cfg)
            except Exception as e:
                logger.warning("Could not read sender config file: %s", e)

        if overrides:
            for k, v in overrides.items():
                if v is not None:
                    cfg[k] = v

        return cfg

    def start(self):
        """Start the Sender Agent main loop."""
        self.running = True
        logger.info("Initializing Sender Agent (Device ID: %s)...", self.device_id)

        # 1. Register device with central server
        os_info = get_operating_system_info()
        interfaces = get_interfaces_detail()
        primary_if = get_primary_interface()

        meta = {
            "device_type": "sender",
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
                logger.info("Sender successfully registered with Flask server.")
                break
            logger.warning("Registration failed. Server may be down. Retrying...")
            self.communicator.handle_reconnect_sleep()

        # 2. Launch background heartbeat daemon
        hb_thread = threading.Thread(target=self._heartbeat_loop, name="SenderHeartbeat", daemon=True)
        hb_thread.start()

        # 3. Main task polling loop
        logger.info("Sender Agent online and polling for test commands.")
        try:
            while self.running:
                tasks = self.communicator.fetch_pending_tasks()
                for task in tasks:
                    self._handle_task(task)
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal. Shutting down Sender Agent...")
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
        """Dispatch task command received from central server."""
        task_type = task.get("task_type")
        task_id = task.get("task_id")
        payload = task.get("payload", {})

        logger.info("Sender received task: %s (ID: %s)", task_type, task_id)

        if task_type == "run_test":
            # Launch in background thread so heartbeats are not blocked
            self.active_test_thread = threading.Thread(
                target=self._execute_test_task,
                args=(task_id, payload),
                daemon=True
            )
            self.active_test_thread.start()
        elif task_type == "ping_check":
            target = payload.get("target", "127.0.0.1")
            res = self.orchestrator.execute_test_suite(target, ["icmp_ping"], duration_sec=3)
            self.communicator.report_task_result(task_id, "completed", res)

    def _execute_test_task(self, task_id: str, payload: Dict[str, Any]):
        """Run full network testing suite and report results."""
        target_ip = payload.get("receiver_ip", "127.0.0.1")
        test_modes = payload.get("test_modes", ["icmp_ping", "rtt", "jitter", "loss", "tcp_throughput"])
        duration = int(payload.get("duration_sec", 15))
        packet_size = int(payload.get("packet_size_bytes", 64))
        interval = float(payload.get("interval_sec", 0.5))
        direction = payload.get("direction", "sender_to_receiver")
        iperf_port = int(payload.get("iperf_port", 5201))

        logger.info("Executing test suite against Receiver %s (modes=%s, duration=%ds)", target_ip, test_modes, duration)

        try:
            results = self.orchestrator.execute_test_suite(
                target_ip=target_ip,
                test_modes=test_modes,
                duration_sec=duration,
                packet_size=packet_size,
                interval_sec=interval,
                direction=direction,
                iperf_port=iperf_port,
                role="sender"
            )
            self.communicator.report_task_result(task_id, "completed", results)
            logger.info("Test %s completed successfully and reported to server.", task_id)
        except Exception as e:
            logger.error("Error executing test task %s: %s", task_id, e)
            self.communicator.report_task_result(task_id, "failed", {"error": str(e)})

    def stop(self):
        """Stop agent and clean up resources."""
        self.running = False
        logger.info("Sender Agent terminated.")


def parse_args():
    parser = argparse.ArgumentParser(description="Sender Network Testing Agent (Device 1)")
    parser.add_argument("--server", type=str, help="Flask central server URL (e.g. http://192.168.1.50:5000)")
    parser.add_argument("--id", type=str, help="Device ID")
    parser.add_argument("--token", type=str, help="Authentication API Token")
    parser.add_argument("--interface", type=str, help="Network interface name to monitor")
    parser.add_argument("--config", type=str, help="Path to sender_config.json")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    overrides = {
        "server_url": args.server,
        "device_id": args.id,
        "auth_token": args.token,
        "interface_name": args.interface
    }
    agent = SenderAgent(config_path=args.config, overrides=overrides)
    agent.start()
