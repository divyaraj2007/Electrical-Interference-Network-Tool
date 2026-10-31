"""
Database management module for Electrical Interference Investigation Tool.
Implements parameterized SQLite storage, schema initialization, and query interfaces.
"""

import sqlite3
import os
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "investigation.db")


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create and return a database connection with row factory enabled."""
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize SQLite database schema with all required tables and indexes."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Monitoring Sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        target TEXT NOT NULL,
        interval_sec REAL NOT NULL DEFAULT 1.0,
        duration_sec INTEGER NOT NULL DEFAULT 60,
        packet_count INTEGER DEFAULT NULL,
        timeout_sec REAL NOT NULL DEFAULT 2.0,
        mode TEXT NOT NULL DEFAULT 'single', -- 'single', 'continuous', 'multi_target'
        status TEXT NOT NULL DEFAULT 'created', -- 'created', 'running', 'stopped', 'completed', 'error'
        start_time TEXT,
        end_time TEXT,
        is_demo INTEGER NOT NULL DEFAULT 0,
        notes TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
    );
    """)

    # 2. Ping Measurements table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ping_measurements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        target_role TEXT DEFAULT 'target', -- 'gateway', 'local_peer', 'dns', 'internet', 'target'
        sequence_num INTEGER NOT NULL,
        rtt_ms REAL,
        success INTEGER NOT NULL DEFAULT 1,
        timeout INTEGER NOT NULL DEFAULT 0,
        error_msg TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    """)

    # 3. Interface Statistics table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS interface_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        interface_name TEXT NOT NULL,
        bytes_sent INTEGER NOT NULL DEFAULT 0,
        bytes_recv INTEGER NOT NULL DEFAULT 0,
        packets_sent INTEGER NOT NULL DEFAULT 0,
        packets_recv INTEGER NOT NULL DEFAULT 0,
        rx_errors INTEGER NOT NULL DEFAULT 0,
        tx_errors INTEGER NOT NULL DEFAULT 0,
        rx_drops INTEGER NOT NULL DEFAULT 0,
        tx_drops INTEGER NOT NULL DEFAULT 0,
        crc_fcs_errors INTEGER NOT NULL DEFAULT 0,
        rx_errors_delta INTEGER NOT NULL DEFAULT 0,
        tx_errors_delta INTEGER NOT NULL DEFAULT 0,
        rx_drops_delta INTEGER NOT NULL DEFAULT 0,
        crc_fcs_delta INTEGER NOT NULL DEFAULT 0,
        link_speed_mbps INTEGER DEFAULT 0,
        is_up INTEGER NOT NULL DEFAULT 1,
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
    );
    """)

    # 4. Packet Captures (Wireshark/TShark) table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packet_captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        interface_name TEXT NOT NULL,
        duration_sec REAL NOT NULL DEFAULT 0,
        packet_count INTEGER NOT NULL DEFAULT 0,
        file_size_bytes INTEGER NOT NULL DEFAULT 0,
        tcp_retransmissions INTEGER DEFAULT 0,
        dup_acks INTEGER DEFAULT 0,
        dns_failures INTEGER DEFAULT 0,
        tcp_resets INTEGER DEFAULT 0,
        protocol_summary TEXT, -- JSON dictionary of protocols
        analysis_notes TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
    );
    """)

    # 5. Electrical Interference Incidents table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        title TEXT NOT NULL,
        location TEXT NOT NULL,
        equipment_involved TEXT,
        cable_type TEXT NOT NULL, -- Cat5e UTP, Cat6 UTP, Cat6a STP, etc.
        cable_length_m REAL,
        distance_to_source_m REAL,
        equipment_operating INTEGER NOT NULL DEFAULT 0,
        electrical_source_type TEXT, -- 'motor', 'vfd', 'elevator', 'transformer', 'welder', 'hvac', 'other'
        baseline_latency REAL,
        incident_latency REAL,
        baseline_loss REAL,
        incident_loss REAL,
        crc_fcs_observed INTEGER DEFAULT 0,
        isolation_test_result TEXT,
        investigator_notes TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL
    );
    """)

    # 6. Comparative Tests (Test A, B, C, D) table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS comparative_tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        test_code TEXT NOT NULL, -- 'A', 'B', 'C', 'D'
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        duration_sec INTEGER NOT NULL DEFAULT 60,
        avg_rtt REAL,
        min_rtt REAL,
        max_rtt REAL,
        packet_loss_pct REAL,
        crc_error_delta INTEGER DEFAULT 0,
        packets_transmitted INTEGER DEFAULT 0,
        packets_received INTEGER DEFAULT 0,
        observations TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
    """)

    # 7. SNMP Switch Configurations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS snmp_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        switch_name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 161,
        community TEXT NOT NULL DEFAULT 'public',
        snmp_version TEXT NOT NULL DEFAULT '2c',
        if_index INTEGER NOT NULL DEFAULT 1,
        port_name TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
    );
    """)

    # 8. Investigation & Correlation Analysis Results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        incident_id INTEGER,
        category TEXT NOT NULL, -- 'physical_layer_emi', 'congestion', 'routing_gateway', 'dns_application', 'insufficient_evidence'
        confidence_score REAL NOT NULL, -- 0.0 to 100.0%
        rtt_baseline_avg REAL,
        rtt_incident_avg REAL,
        rtt_delta_pct REAL,
        loss_baseline_pct REAL,
        loss_incident_pct REAL,
        crc_fcs_total_delta INTEGER DEFAULT 0,
        findings_json TEXT, -- JSON array of findings
        recommendations_json TEXT, -- JSON array of recommendations
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL,
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
    );
    """)

    # 9. Registered Devices (Sender & Receiver Agents)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE NOT NULL,
        device_type TEXT NOT NULL DEFAULT 'sender', -- 'sender', 'receiver'
        hostname TEXT,
        ip_address TEXT,
        os_info TEXT,
        interfaces_json TEXT,
        agent_version TEXT DEFAULT '1.0.0',
        auth_token TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'offline', -- 'online', 'offline', 'testing'
        last_heartbeat TEXT,
        cpu_pct REAL DEFAULT 0.0,
        mem_pct REAL DEFAULT 0.0,
        active_interface TEXT,
        link_speed_mbps INTEGER DEFAULT 0,
        rx_errors INTEGER DEFAULT 0,
        tx_errors INTEGER DEFAULT 0,
        rx_drops INTEGER DEFAULT 0,
        tx_drops INTEGER DEFAULT 0,
        crc_fcs_errors INTEGER DEFAULT 0,
        crc_supported INTEGER DEFAULT 0, -- 1 if supported, 0 if unsupported/not exposed
        config_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
    );
    """)

    # 10. Coordinated Two-Device Testing Sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_device_tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_uuid TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        incident_id INTEGER,
        sender_device_id TEXT NOT NULL,
        receiver_device_id TEXT NOT NULL,
        direction TEXT NOT NULL DEFAULT 'sender_to_receiver', -- 'sender_to_receiver', 'receiver_to_sender', 'bidirectional'
        test_modes_json TEXT NOT NULL,
        duration_sec INTEGER NOT NULL DEFAULT 30,
        packet_size_bytes INTEGER NOT NULL DEFAULT 64,
        interval_sec REAL NOT NULL DEFAULT 1.0,
        equipment_state TEXT DEFAULT 'off', -- 'on', 'off', 'before_cable_replacement', 'after_cable_replacement'
        status TEXT NOT NULL DEFAULT 'created', -- 'created', 'running', 'completed', 'stopped', 'failed'
        start_time TEXT,
        end_time TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
    );
    """)

    # 11. Two-Device Telemetry & Measurements
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_device_measurements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_id INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        device_role TEXT NOT NULL, -- 'sender', 'receiver'
        metric_type TEXT NOT NULL, -- 'ping', 'jitter', 'loss', 'throughput_tcp', 'throughput_udp', 'dns', 'traceroute', 'mtu', 'interface_stats', 'system_stats', 'error'
        sequence_num INTEGER DEFAULT 0,
        value_numeric REAL DEFAULT 0.0,
        data_json TEXT NOT NULL,
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (test_id) REFERENCES two_device_tests(id) ON DELETE CASCADE
    );
    """)

    # 12. Two-Device Investigation & EMI Analysis
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS two_device_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_id INTEGER NOT NULL,
        incident_id INTEGER,
        category TEXT NOT NULL,
        confidence_score REAL NOT NULL,
        rtt_avg REAL,
        jitter_ms REAL,
        loss_pct REAL,
        sender_throughput_mbps REAL,
        receiver_throughput_mbps REAL,
        retransmissions INTEGER DEFAULT 0,
        sender_errors_delta INTEGER DEFAULT 0,
        receiver_errors_delta INTEGER DEFAULT 0,
        sender_crc_delta INTEGER DEFAULT 0,
        receiver_crc_delta INTEGER DEFAULT 0,
        findings_json TEXT,
        recommendations_json TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (test_id) REFERENCES two_device_tests(id) ON DELETE CASCADE,
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
    );
    """)

    # 13. Agent Tasks Queue
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        task_type TEXT NOT NULL,
        task_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'dispatched', 'completed', 'failed', 'cancelled'
        result_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        updated_at TEXT
    );
    """)

    # Indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ping_session ON ping_measurements(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ping_time ON ping_measurements(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ifstats_session ON interface_stats(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_captures_session ON packet_captures(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tests_incident ON comparative_tests(incident_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_id ON devices(device_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(auth_token);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_two_tests_uuid ON two_device_tests(test_uuid);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_two_meas_test ON two_device_measurements(test_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_two_meas_time ON two_device_measurements(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_tasks_dev ON agent_tasks(device_id, status);")

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully at %s", db_path)


# ============================================================================
# Session Operations
# ============================================================================

def create_session(name: str, target: str, interval_sec: float = 1.0,
                   duration_sec: int = 60, packet_count: Optional[int] = None,
                   timeout_sec: float = 2.0, mode: str = 'single',
                   notes: str = "", is_demo: int = 0,
                   db_path: str = DEFAULT_DB_PATH) -> int:
    """Create a new monitoring session and return its ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sessions (name, target, interval_sec, duration_sec, packet_count,
                              timeout_sec, mode, status, notes, is_demo)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'created', ?, ?)
    """, (name, target, interval_sec, duration_sec, packet_count, timeout_sec, mode, notes, is_demo))
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id


def start_session(session_id: int, db_path: str = DEFAULT_DB_PATH) -> None:
    """Mark session as running with start timestamp."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE sessions SET status = 'running', start_time = ? WHERE id = ?
    """, (now, session_id))
    conn.commit()
    conn.close()


def end_session(session_id: int, status: str = 'completed', db_path: str = DEFAULT_DB_PATH) -> None:
    """Mark session as completed or stopped with end timestamp."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE sessions SET status = ?, end_time = ? WHERE id = ?
    """, (status, now, session_id))
    conn.commit()
    conn.close()


def get_session(session_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve session details by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_active_session(db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve currently running session if any."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE status = 'running' ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_sessions(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all sessions ordered by creation date."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# Ping Measurements Operations
# ============================================================================

def record_ping_measurement(session_id: int, target: str, sequence_num: int,
                            rtt_ms: Optional[float], success: bool,
                            timeout: bool = False, error_msg: Optional[str] = None,
                            target_role: str = 'target',
                            timestamp: Optional[str] = None,
                            db_path: str = DEFAULT_DB_PATH) -> int:
    """Insert a single ping measurement record."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO ping_measurements (session_id, target, target_role, sequence_num,
                                       rtt_ms, success, timeout, error_msg, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, target, target_role, sequence_num, rtt_ms, 1 if success else 0,
          1 if timeout else 0, error_msg, ts))
    measurement_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return measurement_id


def get_session_ping_measurements(session_id: int, target: Optional[str] = None,
                                  db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all ping measurements for a session, optionally filtered by target."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if target:
        cursor.execute("""
            SELECT * FROM ping_measurements
            WHERE session_id = ? AND target = ?
            ORDER BY sequence_num ASC
        """, (session_id, target))
    else:
        cursor.execute("""
            SELECT * FROM ping_measurements
            WHERE session_id = ?
            ORDER BY sequence_num ASC
        """, (session_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_ping_measurements(session_id: int, limit: int = 100,
                                 db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve the most recent N ping measurements for live graph updates."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM ping_measurements
        WHERE session_id = ?
        ORDER BY id DESC LIMIT ?
    """, (session_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in reversed(rows)]


def get_ping_summary(session_id: int, target: Optional[str] = None,
                     db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Calculate aggregate summary metrics for a ping session."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    query = """
        SELECT
            COUNT(*) as total_packets,
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_packets,
            SUM(CASE WHEN timeout = 1 OR success = 0 THEN 1 ELSE 0 END) as lost_packets,
            AVG(CASE WHEN success = 1 THEN rtt_ms ELSE NULL END) as avg_rtt,
            MIN(CASE WHEN success = 1 THEN rtt_ms ELSE NULL END) as min_rtt,
            MAX(CASE WHEN success = 1 THEN rtt_ms ELSE NULL END) as max_rtt
        FROM ping_measurements
        WHERE session_id = ?
    """
    params: List[Any] = [session_id]
    if target:
        query += " AND target = ?"
        params.append(target)

    cursor.execute(query, params)
    row = cursor.fetchone()
    conn.close()

    if not row or row["total_packets"] == 0:
        return {
            "total_packets": 0,
            "successful_packets": 0,
            "lost_packets": 0,
            "loss_pct": 0.0,
            "avg_rtt": 0.0,
            "min_rtt": 0.0,
            "max_rtt": 0.0
        }

    total = row["total_packets"]
    lost = row["lost_packets"] or 0
    loss_pct = round((lost / total) * 100.0, 2) if total > 0 else 0.0

    return {
        "total_packets": total,
        "successful_packets": row["successful_packets"] or 0,
        "lost_packets": lost,
        "loss_pct": loss_pct,
        "avg_rtt": round(row["avg_rtt"], 2) if row["avg_rtt"] is not None else 0.0,
        "min_rtt": round(row["min_rtt"], 2) if row["min_rtt"] is not None else 0.0,
        "max_rtt": round(row["max_rtt"], 2) if row["max_rtt"] is not None else 0.0
    }


# ============================================================================
# Interface Statistics Operations
# ============================================================================

def record_interface_stats(stats: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record a snapshot of physical network interface counters."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO interface_stats (
            session_id, interface_name, bytes_sent, bytes_recv,
            packets_sent, packets_recv, rx_errors, tx_errors,
            rx_drops, tx_drops, crc_fcs_errors, rx_errors_delta,
            tx_errors_delta, rx_drops_delta, crc_fcs_delta,
            link_speed_mbps, is_up, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        stats.get("session_id"),
        stats.get("interface_name", "unknown"),
        stats.get("bytes_sent", 0),
        stats.get("bytes_recv", 0),
        stats.get("packets_sent", 0),
        stats.get("packets_recv", 0),
        stats.get("rx_errors", 0),
        stats.get("tx_errors", 0),
        stats.get("rx_drops", 0),
        stats.get("tx_drops", 0),
        stats.get("crc_fcs_errors", 0),
        stats.get("rx_errors_delta", 0),
        stats.get("tx_errors_delta", 0),
        stats.get("rx_drops_delta", 0),
        stats.get("crc_fcs_delta", 0),
        stats.get("link_speed_mbps", 0),
        1 if stats.get("is_up", True) else 0,
        stats.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ))
    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return record_id


def get_recent_interface_stats(session_id: Optional[int] = None, limit: int = 50,
                               db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve recent interface statistics for graphing."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("""
            SELECT * FROM interface_stats
            WHERE session_id = ?
            ORDER BY id DESC LIMIT ?
        """, (session_id, limit))
    else:
        cursor.execute("SELECT * FROM interface_stats ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in reversed(rows)]


# ============================================================================
# Packet Capture Operations
# ============================================================================

def record_packet_capture(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record metadata and analysis from a Wireshark/TShark capture session."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    proto_json = json.dumps(data.get("protocol_summary", {}))
    cursor.execute("""
        INSERT INTO packet_captures (
            session_id, filename, filepath, interface_name, duration_sec,
            packet_count, file_size_bytes, tcp_retransmissions, dup_acks,
            dns_failures, tcp_resets, protocol_summary, analysis_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("session_id"),
        data.get("filename", "capture.pcapng"),
        data.get("filepath", ""),
        data.get("interface_name", "all"),
        data.get("duration_sec", 0.0),
        data.get("packet_count", 0),
        data.get("file_size_bytes", 0),
        data.get("tcp_retransmissions", 0),
        data.get("dup_acks", 0),
        data.get("dns_failures", 0),
        data.get("tcp_resets", 0),
        proto_json,
        data.get("analysis_notes", "")
    ))
    cid = cursor.lastrowid
    conn.commit()
    conn.close()
    return cid


def get_packet_captures(session_id: Optional[int] = None, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve packet capture metadata."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if session_id:
        cursor.execute("SELECT * FROM packet_captures WHERE session_id = ? ORDER BY id DESC", (session_id,))
    else:
        cursor.execute("SELECT * FROM packet_captures ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if d.get("protocol_summary"):
            try:
                d["protocol_summary"] = json.loads(d["protocol_summary"])
            except Exception:
                d["protocol_summary"] = {}
        results.append(d)
    return results


# ============================================================================
# Incident & Comparative Test Operations
# ============================================================================

def create_incident(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record an electrical interference incident investigation report."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO incidents (
            session_id, title, location, equipment_involved, cable_type,
            cable_length_m, distance_to_source_m, equipment_operating,
            electrical_source_type, baseline_latency, incident_latency,
            baseline_loss, incident_loss, crc_fcs_observed,
            isolation_test_result, investigator_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("session_id"),
        data.get("title", "Interference Investigation"),
        data.get("location", "Office/Factory"),
        data.get("equipment_involved", ""),
        data.get("cable_type", "Cat6 UTP"),
        data.get("cable_length_m", 15.0),
        data.get("distance_to_source_m", 0.5),
        1 if data.get("equipment_operating", False) else 0,
        data.get("electrical_source_type", "motor"),
        data.get("baseline_latency", 0.0),
        data.get("incident_latency", 0.0),
        data.get("baseline_loss", 0.0),
        data.get("incident_loss", 0.0),
        data.get("crc_fcs_observed", 0),
        data.get("isolation_test_result", ""),
        data.get("investigator_notes", "")
    ))
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return incident_id


def get_incidents(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all logged incidents."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incident(incident_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve a single incident by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def record_comparative_test(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record a test observation period (Test A, B, C, or D)."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO comparative_tests (
            incident_id, test_code, title, description, duration_sec,
            avg_rtt, min_rtt, max_rtt, packet_loss_pct, crc_error_delta,
            packets_transmitted, packets_received, observations
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("incident_id"),
        data.get("test_code", "A"),
        data.get("title", "Test"),
        data.get("description", ""),
        data.get("duration_sec", 60),
        data.get("avg_rtt", 0.0),
        data.get("min_rtt", 0.0),
        data.get("max_rtt", 0.0),
        data.get("packet_loss_pct", 0.0),
        data.get("crc_error_delta", 0),
        data.get("packets_transmitted", 0),
        data.get("packets_received", 0),
        data.get("observations", "")
    ))
    test_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return test_id


def get_comparative_tests(incident_id: int, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve comparative tests for an incident ordered by test code."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM comparative_tests
        WHERE incident_id = ?
        ORDER BY test_code ASC
    """, (incident_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# Analysis Results & SNMP Operations
# ============================================================================

def record_analysis_result(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Persist diagnosis results and recommendations."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    findings = json.dumps(data.get("findings", []))
    recommendations = json.dumps(data.get("recommendations", []))
    cursor.execute("""
        INSERT INTO analysis_results (
            session_id, incident_id, category, confidence_score,
            rtt_baseline_avg, rtt_incident_avg, rtt_delta_pct,
            loss_baseline_pct, loss_incident_pct, crc_fcs_total_delta,
            findings_json, recommendations_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("session_id"),
        data.get("incident_id"),
        data.get("category", "insufficient_evidence"),
        data.get("confidence_score", 0.0),
        data.get("rtt_baseline_avg", 0.0),
        data.get("rtt_incident_avg", 0.0),
        data.get("rtt_delta_pct", 0.0),
        data.get("loss_baseline_pct", 0.0),
        data.get("loss_incident_pct", 0.0),
        data.get("crc_fcs_total_delta", 0),
        findings,
        recommendations
    ))
    aid = cursor.lastrowid
    conn.commit()
    conn.close()
    return aid


def get_latest_analysis(session_id: Optional[int] = None,
                        incident_id: Optional[int] = None,
                        db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve the most recent analysis result."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if incident_id:
        cursor.execute("SELECT * FROM analysis_results WHERE incident_id = ? ORDER BY id DESC LIMIT 1", (incident_id,))
    elif session_id:
        cursor.execute("SELECT * FROM analysis_results WHERE session_id = ? ORDER BY id DESC LIMIT 1", (session_id,))
    else:
        cursor.execute("SELECT * FROM analysis_results ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["findings"] = json.loads(d.get("findings_json") or "[]")
        d["recommendations"] = json.loads(d.get("recommendations_json") or "[]")
    except Exception:
        d["findings"] = []
        d["recommendations"] = []
    return d


def save_snmp_config(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Save an SNMP switch port monitoring profile."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO snmp_configs (switch_name, host, port, community, snmp_version, if_index, port_name)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("switch_name", "Switch"),
        data.get("host", "192.168.1.1"),
        data.get("port", 161),
        data.get("community", "public"),
        data.get("snmp_version", "2c"),
        data.get("if_index", 1),
        data.get("port_name", "GigabitEthernet0/1")
    ))
    cid = cursor.lastrowid
    conn.commit()
    conn.close()
    return cid


def get_snmp_configs(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve all saved SNMP switch configurations."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM snmp_configs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================================
# Two-Device System & Agent Management Operations
# ============================================================================

def upsert_device(device_data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Register or update an agent device (Sender or Receiver)."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    dev_id = device_data.get("device_id")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT * FROM devices WHERE device_id = ?", (dev_id,))
    existing = cursor.fetchone()

    interfaces_json = device_data.get("interfaces_json")
    if isinstance(interfaces_json, (list, dict)):
        interfaces_json = json.dumps(interfaces_json)

    config_json = device_data.get("config_json")
    if isinstance(config_json, (list, dict)):
        config_json = json.dumps(config_json)

    if existing:
        cursor.execute("""
            UPDATE devices SET
                device_type = ?,
                hostname = ?,
                ip_address = ?,
                os_info = ?,
                interfaces_json = coalesce(?, interfaces_json),
                agent_version = ?,
                auth_token = coalesce(?, auth_token),
                status = 'online',
                last_heartbeat = ?,
                cpu_pct = ?,
                mem_pct = ?,
                active_interface = ?,
                link_speed_mbps = ?,
                rx_errors = ?,
                tx_errors = ?,
                rx_drops = ?,
                tx_drops = ?,
                crc_fcs_errors = ?,
                crc_supported = ?,
                config_json = coalesce(?, config_json)
            WHERE device_id = ?
        """, (
            device_data.get("device_type", existing["device_type"]),
            device_data.get("hostname", existing["hostname"]),
            device_data.get("ip_address", existing["ip_address"]),
            device_data.get("os_info", existing["os_info"]),
            interfaces_json,
            device_data.get("agent_version", existing["agent_version"]),
            device_data.get("auth_token", existing["auth_token"]),
            now,
            device_data.get("cpu_pct", existing["cpu_pct"] or 0.0),
            device_data.get("mem_pct", existing["mem_pct"] or 0.0),
            device_data.get("active_interface", existing["active_interface"]),
            device_data.get("link_speed_mbps", existing["link_speed_mbps"] or 0),
            device_data.get("rx_errors", existing["rx_errors"] or 0),
            device_data.get("tx_errors", existing["tx_errors"] or 0),
            device_data.get("rx_drops", existing["rx_drops"] or 0),
            device_data.get("tx_drops", existing["tx_drops"] or 0),
            device_data.get("crc_fcs_errors", existing["crc_fcs_errors"] or 0),
            device_data.get("crc_supported", existing["crc_supported"] or 0),
            config_json,
            dev_id
        ))
    else:
        cursor.execute("""
            INSERT INTO devices (
                device_id, device_type, hostname, ip_address, os_info,
                interfaces_json, agent_version, auth_token, status,
                last_heartbeat, cpu_pct, mem_pct, active_interface,
                link_speed_mbps, rx_errors, tx_errors, rx_drops, tx_drops,
                crc_fcs_errors, crc_supported, config_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            dev_id,
            device_data.get("device_type", "sender"),
            device_data.get("hostname", "Unknown"),
            device_data.get("ip_address", "127.0.0.1"),
            device_data.get("os_info", "Unknown OS"),
            interfaces_json,
            device_data.get("agent_version", "1.0.0"),
            device_data.get("auth_token", ""),
            now,
            device_data.get("cpu_pct", 0.0),
            device_data.get("mem_pct", 0.0),
            device_data.get("active_interface", ""),
            device_data.get("link_speed_mbps", 0),
            device_data.get("rx_errors", 0),
            device_data.get("tx_errors", 0),
            device_data.get("rx_drops", 0),
            device_data.get("tx_drops", 0),
            device_data.get("crc_fcs_errors", 0),
            device_data.get("crc_supported", 0),
            config_json,
            now
        ))

    conn.commit()
    cursor.execute("SELECT * FROM devices WHERE device_id = ?", (dev_id,))
    row = cursor.fetchone()
    conn.close()
    return _format_device_row(row) if row else {}


def _format_device_row(row) -> Dict[str, Any]:
    if not row:
        return {}
    d = dict(row)
    try:
        d["interfaces"] = json.loads(d.get("interfaces_json") or "[]")
    except Exception:
        d["interfaces"] = []
    try:
        d["config"] = json.loads(d.get("config_json") or "{}")
    except Exception:
        d["config"] = {}

    # Check online/offline dynamically: offline if last_heartbeat is older than 25 seconds
    if d.get("last_heartbeat"):
        try:
            hb_time = datetime.strptime(d["last_heartbeat"], "%Y-%m-%d %H:%M:%S")
            diff = (datetime.now() - hb_time).total_seconds()
            if diff > 25.0:
                d["status"] = "offline"
        except Exception:
            pass
    return d


def get_device_by_id(device_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve device by device_id."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = cursor.fetchone()
    conn.close()
    return _format_device_row(row) if row else None


def get_device_by_token(auth_token: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve device by auth token."""
    if not auth_token:
        return None
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE auth_token = ?", (auth_token,))
    row = cursor.fetchone()
    conn.close()
    return _format_device_row(row) if row else None


def get_all_devices(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """List all registered devices with their current health and online status."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [_format_device_row(r) for r in rows]


def update_device_heartbeat(device_id: str, telemetry: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> bool:
    """Update last heartbeat timestamp and real-time interface telemetry."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE devices SET
            last_heartbeat = ?,
            status = 'online',
            cpu_pct = coalesce(?, cpu_pct),
            mem_pct = coalesce(?, mem_pct),
            active_interface = coalesce(?, active_interface),
            link_speed_mbps = coalesce(?, link_speed_mbps),
            rx_errors = coalesce(?, rx_errors),
            tx_errors = coalesce(?, tx_errors),
            rx_drops = coalesce(?, rx_drops),
            tx_drops = coalesce(?, tx_drops),
            crc_fcs_errors = coalesce(?, crc_fcs_errors),
            crc_supported = coalesce(?, crc_supported)
        WHERE device_id = ?
    """, (
        now,
        telemetry.get("cpu_pct"),
        telemetry.get("mem_pct"),
        telemetry.get("active_interface"),
        telemetry.get("link_speed_mbps"),
        telemetry.get("rx_errors"),
        telemetry.get("tx_errors"),
        telemetry.get("rx_drops"),
        telemetry.get("tx_drops"),
        telemetry.get("crc_fcs_errors"),
        telemetry.get("crc_supported"),
        device_id
    ))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


def update_device_status(device_id: str, status: str, db_path: str = DEFAULT_DB_PATH) -> None:
    """Update device status ('online', 'offline', 'testing')."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET status = ? WHERE device_id = ?", (status, device_id))
    conn.commit()
    conn.close()


def delete_device(device_id: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Delete a registered device."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
    deleted = cursor.rowcount > 0
    cursor.execute("DELETE FROM agent_tasks WHERE device_id = ?", (device_id,))
    conn.commit()
    conn.close()
    return deleted


# ============================================================================
# Agent Task Queue Operations
# ============================================================================

def create_agent_task(device_id: str, task_type: str, payload: Dict[str, Any],
                      task_id: Optional[str] = None, db_path: str = DEFAULT_DB_PATH) -> int:
    """Queue a task command for an agent."""
    import uuid
    if not task_id:
        task_id = str(uuid.uuid4())
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO agent_tasks (device_id, task_type, task_id, payload_json, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
    """, (device_id, task_type, task_id, json.dumps(payload), now))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_pending_agent_tasks(device_id: str, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieve pending tasks for an agent and mark them dispatched."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM agent_tasks
        WHERE device_id = ? AND status = 'pending'
        ORDER BY id ASC
    """, (device_id,))
    rows = cursor.fetchall()
    tasks = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for r in rows:
        t = dict(r)
        try:
            t["payload"] = json.loads(t.get("payload_json") or "{}")
        except Exception:
            t["payload"] = {}
        tasks.append(t)
        cursor.execute("UPDATE agent_tasks SET status = 'dispatched', updated_at = ? WHERE id = ?", (now, r["id"]))
    conn.commit()
    conn.close()
    return tasks


def update_agent_task(task_id: str, status: str, result: Optional[Dict[str, Any]] = None,
                      db_path: str = DEFAULT_DB_PATH) -> bool:
    """Update task completion status and result."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    res_str = json.dumps(result) if result is not None else None
    cursor.execute("""
        UPDATE agent_tasks SET status = ?, result_json = coalesce(?, result_json), updated_at = ?
        WHERE task_id = ?
    """, (status, res_str, now, task_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated


# ============================================================================
# Two-Device Testing Session Operations
# ============================================================================

def create_two_device_test(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Create a coordinated two-device test record."""
    import uuid
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    test_uuid = data.get("test_uuid") or str(uuid.uuid4())
    modes = data.get("test_modes", [])
    if isinstance(modes, list):
        modes_json = json.dumps(modes)
    else:
        modes_json = str(modes)

    cursor.execute("""
        INSERT INTO two_device_tests (
            test_uuid, name, incident_id, sender_device_id, receiver_device_id,
            direction, test_modes_json, duration_sec, packet_size_bytes,
            interval_sec, equipment_state, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created')
    """, (
        test_uuid,
        data.get("name", f"Two-Device Test {datetime.now().strftime('%Y-%m-%d %H:%M')}"),
        data.get("incident_id"),
        data.get("sender_device_id"),
        data.get("receiver_device_id"),
        data.get("direction", "sender_to_receiver"),
        modes_json,
        int(data.get("duration_sec", 30)),
        int(data.get("packet_size_bytes", 64)),
        float(data.get("interval_sec", 1.0)),
        data.get("equipment_state", "off")
    ))
    test_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return test_id


def get_two_device_test(test_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve two-device test by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM two_device_tests WHERE id = ?", (test_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["test_modes"] = json.loads(d.get("test_modes_json") or "[]")
    except Exception:
        d["test_modes"] = []
    try:
        d["summary"] = json.loads(d.get("summary_json") or "{}")
    except Exception:
        d["summary"] = {}
    return d


def get_two_device_test_by_uuid(test_uuid: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve two-device test by UUID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM two_device_tests WHERE test_uuid = ?", (test_uuid,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["test_modes"] = json.loads(d.get("test_modes_json") or "[]")
    except Exception:
        d["test_modes"] = []
    try:
        d["summary"] = json.loads(d.get("summary_json") or "{}")
    except Exception:
        d["summary"] = {}
    return d


def update_two_device_test(test_id: int, update_data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> None:
    """Update status, timestamps, or summary of a two-device test."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    summary = update_data.get("summary")
    summary_json = json.dumps(summary) if isinstance(summary, (dict, list)) else summary

    cursor.execute("""
        UPDATE two_device_tests SET
            status = coalesce(?, status),
            start_time = coalesce(?, start_time),
            end_time = coalesce(?, end_time),
            summary_json = coalesce(?, summary_json)
        WHERE id = ?
    """, (
        update_data.get("status"),
        update_data.get("start_time"),
        update_data.get("end_time"),
        summary_json,
        test_id
    ))
    conn.commit()
    conn.close()


def get_all_two_device_tests(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """List historical two-device tests."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM two_device_tests ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        try:
            d["test_modes"] = json.loads(d.get("test_modes_json") or "[]")
        except Exception:
            d["test_modes"] = []
        try:
            d["summary"] = json.loads(d.get("summary_json") or "{}")
        except Exception:
            d["summary"] = {}
        res.append(d)
    return res


def record_two_device_measurement(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Record an individual metric or telemetry point from Sender or Receiver."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    data_json = data.get("data")
    if isinstance(data_json, (dict, list)):
        data_json = json.dumps(data_json)
    elif data_json is None:
        data_json = "{}"

    now = data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO two_device_measurements (
            test_id, device_id, device_role, metric_type, sequence_num,
            value_numeric, data_json, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("test_id"),
        data.get("device_id"),
        data.get("device_role", "sender"),
        data.get("metric_type", "ping"),
        data.get("sequence_num", 0),
        data.get("value_numeric", 0.0),
        data_json,
        now
    ))
    mid = cursor.lastrowid
    conn.commit()
    conn.close()
    return mid


def get_two_device_measurements(test_id: int, metric_type: Optional[str] = None,
                                limit: int = 1000, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Fetch measurements for a specific test."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if metric_type:
        cursor.execute("""
            SELECT * FROM two_device_measurements
            WHERE test_id = ? AND metric_type = ?
            ORDER BY id ASC LIMIT ?
        """, (test_id, metric_type, limit))
    else:
        cursor.execute("""
            SELECT * FROM two_device_measurements
            WHERE test_id = ?
            ORDER BY id ASC LIMIT ?
        """, (test_id, limit))
    rows = cursor.fetchall()
    conn.close()
    res = []
    for r in rows:
        d = dict(r)
        try:
            d["data"] = json.loads(d.get("data_json") or "{}")
        except Exception:
            d["data"] = {}
        res.append(d)
    return res


def record_two_device_analysis(data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Persist synthesized analysis and root cause finding for a two-device test."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    findings = data.get("findings", [])
    findings_json = json.dumps(findings) if isinstance(findings, list) else str(findings)
    recs = data.get("recommendations", [])
    recs_json = json.dumps(recs) if isinstance(recs, list) else str(recs)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO two_device_analysis (
            test_id, incident_id, category, confidence_score, rtt_avg,
            jitter_ms, loss_pct, sender_throughput_mbps, receiver_throughput_mbps,
            retransmissions, sender_errors_delta, receiver_errors_delta,
            sender_crc_delta, receiver_crc_delta, findings_json, recommendations_json,
            timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("test_id"),
        data.get("incident_id"),
        data.get("category", "insufficient_evidence"),
        data.get("confidence_score", 0.0),
        data.get("rtt_avg", 0.0),
        data.get("jitter_ms", 0.0),
        data.get("loss_pct", 0.0),
        data.get("sender_throughput_mbps", 0.0),
        data.get("receiver_throughput_mbps", 0.0),
        data.get("retransmissions", 0),
        data.get("sender_errors_delta", 0),
        data.get("receiver_errors_delta", 0),
        data.get("sender_crc_delta", 0),
        data.get("receiver_crc_delta", 0),
        findings_json,
        recs_json,
        now
    ))
    aid = cursor.lastrowid
    conn.commit()
    conn.close()
    return aid


def get_two_device_analysis(test_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieve analysis record for a two-device test."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM two_device_analysis WHERE test_id = ? ORDER BY id DESC LIMIT 1", (test_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["findings"] = json.loads(d.get("findings_json") or "[]")
    except Exception:
        d["findings"] = []
    try:
        d["recommendations"] = json.loads(d.get("recommendations_json") or "[]")
    except Exception:
        d["recommendations"] = []
    return d

