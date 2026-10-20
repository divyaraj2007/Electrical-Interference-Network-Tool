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

    # Indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ping_session ON ping_measurements(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ping_time ON ping_measurements(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ifstats_session ON interface_stats(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_captures_session ON packet_captures(session_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tests_incident ON comparative_tests(incident_id);")

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
