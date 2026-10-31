"""
Two-Device Investigation & Scientific EMI Correlation Engine.
Distinguishes between:
  1. Possible Electromagnetic Interference (EMI)
  2. Cable-Related Problems / Shielding Failures
  3. Sender-Side Local Resource/NIC Bottlenecks
  4. Receiver-Side Local Resource/NIC Bottlenecks
  5. Switch-Port / Intermediate Infrastructure Degradation
  6. Network Congestion & Bufferbloat
  7. Gateway / WAN Routing Issues
  8. Insufficient Empirical Evidence
Never assumes EMI without corroborating physical layer or equipment operational correlation.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger("analysis.two_device")


class TwoDeviceRootCause(str, Enum):
    POSSIBLE_EMI = "possible_electromagnetic_interference"
    CABLE_PROBLEM = "cable_defect_or_shielding_failure"
    SENDER_SIDE_PROBLEM = "sender_side_problem"
    RECEIVER_SIDE_PROBLEM = "receiver_side_problem"
    SWITCH_PORT_PROBLEM = "switch_port_or_intermediate_link"
    NETWORK_CONGESTION = "network_congestion"
    GATEWAY_WAN_PROBLEM = "gateway_or_wan_problem"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass
class TwoDeviceDiagnosticResult:
    category: TwoDeviceRootCause
    confidence_score: float  # 0.0 to 100.0%
    summary_title: str
    detailed_findings: List[str] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)
    metrics_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "category_label": self.category.value.replace("_", " ").title(),
            "confidence_score": round(self.confidence_score, 1),
            "summary_title": self.summary_title,
            "findings": self.detailed_findings,
            "recommendations": self.remediation_recommendations,
            "metrics": self.metrics_summary
        }


def analyze_two_device_test(sender_results: Dict[str, Any],
                            receiver_results: Dict[str, Any],
                            equipment_state: str = "off",
                            incident_meta: Optional[Dict[str, Any]] = None,
                            baseline_test: Optional[Dict[str, Any]] = None) -> TwoDeviceDiagnosticResult:
    """
    Synthesize empirical measurements from both devices and determine root cause.
    """
    findings = []
    recommendations = []
    confidence = 50.0

    # Extract sender metrics
    s_metrics = sender_results.get("metrics", {})
    s_ping = s_metrics.get("ping", {})
    s_tcp = s_metrics.get("tcp_throughput", {})
    s_udp = s_metrics.get("udp_throughput", {})
    s_gw_ping = s_metrics.get("gateway_ping", {})
    s_ext_ping = s_metrics.get("external_ping", {})
    s_if_deltas = sender_results.get("interface_deltas", {})
    s_sys = sender_results.get("system_usage", {})

    # Extract receiver metrics
    r_if_deltas = receiver_results.get("interface_deltas", {})
    r_traffic = receiver_results.get("incoming_traffic", {})
    r_sys = receiver_results.get("system_usage", {})

    # Ping indicators
    avg_rtt = s_ping.get("avg_rtt_ms", 0.0)
    max_rtt = s_ping.get("max_rtt_ms", 0.0)
    jitter = s_ping.get("jitter_ms", 0.0)
    loss_pct = s_ping.get("loss_pct", 0.0)

    # Throughput & retransmissions
    s_throughput = s_tcp.get("throughput_mbps", 0.0) or s_udp.get("throughput_mbps", 0.0)
    retransmissions = s_tcp.get("retransmissions", 0)

    # Interface counter deltas
    s_rx_err = s_if_deltas.get("rx_errors_delta", 0)
    s_tx_err = s_if_deltas.get("tx_errors_delta", 0)
    s_drops = s_if_deltas.get("rx_drops_delta", 0) + s_if_deltas.get("tx_drops_delta", 0)
    s_crc = s_if_deltas.get("crc_delta", 0)
    s_crc_supp = s_if_deltas.get("crc_supported", False)

    r_rx_err = r_if_deltas.get("rx_errors_delta", 0)
    r_tx_err = r_if_deltas.get("tx_errors_delta", 0)
    r_drops = r_if_deltas.get("rx_drops_delta", 0) + r_if_deltas.get("tx_drops_delta", 0)
    r_crc = r_if_deltas.get("crc_delta", 0)
    r_crc_supp = r_if_deltas.get("crc_supported", False)

    total_crc = s_crc + r_crc
    total_phy_errors = (s_rx_err + s_tx_err + r_rx_err + r_tx_err)

    # CPU/Mem
    s_cpu = s_sys.get("cpu_after", 0.0)
    r_cpu = r_sys.get("cpu_after", 0.0)

    # External/Gateway health
    gw_loss = s_gw_ping.get("loss_pct", 0.0) if isinstance(s_gw_ping, dict) else 0.0
    ext_loss = s_ext_ping.get("loss_pct", 0.0) if isinstance(s_ext_ping, dict) else 0.0

    # Populate diagnostic findings
    findings.append(f"Sender -> Receiver RTT: avg {avg_rtt:.2f} ms (max {max_rtt:.2f} ms, jitter {jitter:.2f} ms).")
    findings.append(f"Packet Loss: {loss_pct:.1f}%. TCP Retransmissions: {retransmissions}.")
    findings.append(f"Measured Throughput: {s_throughput:.2f} Mbps.")
    findings.append(f"Sender NIC Errors: {s_rx_err + s_tx_err} | Drops: {s_drops} | CRC Delta: {s_crc if s_crc_supp else 'Not exposed by OS'}.")
    findings.append(f"Receiver NIC Errors: {r_rx_err + r_tx_err} | Drops: {r_drops} | CRC Delta: {r_crc if r_crc_supp else 'Not exposed by OS'}.")

    eq_state = str(equipment_state).lower()
    if eq_state == "on":
        findings.append("Electrical equipment status during test: ENERGIZED (ON).")
    elif eq_state == "off":
        findings.append("Electrical equipment status during test: DE-ENERGIZED (OFF/Baseline).")
    elif "replacement" in eq_state:
        findings.append(f"Comparative condition: {equipment_state}.")

    # CLASSIFICATION LOGIC

    # 1. Check for Gateway/WAN isolated failure
    if loss_pct < 1.0 and avg_rtt < 10.0 and (gw_loss > 15.0 or ext_loss > 15.0):
        confidence = 88.0
        findings.append("Local Sender-to-Receiver path is healthy, but gateway/internet destination experienced severe packet loss.")
        recommendations.append("Investigate upstream default gateway, modem/router link, or ISP service provider.")
        recommendations.append("Local physical Ethernet link is not the bottleneck.")
        return TwoDeviceDiagnosticResult(
            category=TwoDeviceRootCause.GATEWAY_WAN_PROBLEM,
            confidence_score=confidence,
            summary_title="Upstream Gateway or WAN Connectivity Problem",
            detailed_findings=findings,
            remediation_recommendations=recommendations,
            metrics_summary={"avg_rtt": avg_rtt, "loss_pct": loss_pct, "gateway_loss": gw_loss}
        )

    # 2. Check for Sender-Side Bottleneck
    if s_cpu > 88.0 and r_cpu < 30.0 and s_drops > 20 and r_drops == 0:
        confidence = 84.0
        findings.append("Sender system CPU exhaustion or outbound driver buffer overrun observed.")
        recommendations.append("Inspect background applications and CPU utilization on Sender Device.")
        recommendations.append("Upgrade Sender network adapter driver or reduce test polling frequency.")
        return TwoDeviceDiagnosticResult(
            category=TwoDeviceRootCause.SENDER_SIDE_PROBLEM,
            confidence_score=confidence,
            summary_title="Sender Device Local Resource Exhaustion",
            detailed_findings=findings,
            remediation_recommendations=recommendations,
            metrics_summary={"sender_cpu": s_cpu, "sender_drops": s_drops}
        )

    # 3. Check for Receiver-Side Bottleneck
    if r_cpu > 88.0 and s_cpu < 30.0 and r_drops > 20:
        confidence = 84.0
        findings.append("Receiver system CPU exhaustion or inbound packet buffer drop observed.")
        recommendations.append("Inspect Receiver system load and increase NIC receive ring buffers.")
        return TwoDeviceDiagnosticResult(
            category=TwoDeviceRootCause.RECEIVER_SIDE_PROBLEM,
            confidence_score=confidence,
            summary_title="Receiver Device Local Resource Exhaustion",
            detailed_findings=findings,
            remediation_recommendations=recommendations,
            metrics_summary={"receiver_cpu": r_cpu, "receiver_drops": r_drops}
        )

    # 4. Check for Physical-Layer EMI / Cable Problem
    is_emi_correlated = False
    if eq_state == "on" and (loss_pct > 2.0 or retransmissions > 5 or total_crc > 0 or total_phy_errors > 0):
        is_emi_correlated = True

    if total_crc > 0 or (is_emi_correlated and (total_phy_errors > 0 or loss_pct >= 3.0)):
        category = TwoDeviceRootCause.POSSIBLE_EMI if eq_state == "on" else TwoDeviceRootCause.CABLE_PROBLEM
        confidence = 90.0 if total_crc > 0 else 78.0
        findings.append("Physical frame check corruption (CRC/FCS) or packet loss coincided directly with electrical state.")
        recommendations.append("Verify cable separation: maintain >= 300 mm (12 in) clearance from high-voltage conduit (ANSI/TIA-568.0-D).")
        recommendations.append("Replace unshielded (UTP) cable with Cat6a S/FTP or Cat7 shielded cable with properly grounded drain wire.")
        recommendations.append("Inspect switch port counters via SNMP to confirm physical CRC discard at the port transceiver.")
        return TwoDeviceDiagnosticResult(
            category=category,
            confidence_score=confidence,
            summary_title="Physical-Layer Degradation Correlated with Electrical Interference / Cabling",
            detailed_findings=findings,
            remediation_recommendations=recommendations,
            metrics_summary={"loss_pct": loss_pct, "total_crc": total_crc, "retransmissions": retransmissions}
        )

    # 5. Check for Network Congestion (high latency without errors)
    if avg_rtt > 30.0 and total_phy_errors == 0 and total_crc == 0 and loss_pct < 3.0:
        confidence = 82.0
        findings.append("Elevated RTT and buffer delay observed without physical frame corruption.")
        recommendations.append("Implement QoS prioritization or active queue management (CoDel/FQ-CoDel) to mitigate bufferbloat.")
        recommendations.append("Check for concurrent heavy bulk file transfers or backup jobs on the subnet.")
        return TwoDeviceDiagnosticResult(
            category=TwoDeviceRootCause.NETWORK_CONGESTION,
            confidence_score=confidence,
            summary_title="Network Queue Congestion & Latency Inflation",
            detailed_findings=findings,
            remediation_recommendations=recommendations,
            metrics_summary={"avg_rtt": avg_rtt, "jitter": jitter, "loss_pct": loss_pct}
        )

    # 6. Check for Switch-Port or Intermediate Link Problem
    if loss_pct > 3.0 and s_drops == 0 and r_drops == 0 and total_phy_errors == 0:
        confidence = 74.0
        findings.append("Packets dropped between Sender and Receiver while both local endpoints report zero NIC errors.")
        recommendations.append("Query managed intermediate switch port via SNMP for discard counters or duplex mismatches.")
        recommendations.append("Test patch panel terminations and intermediate wall jacks.")
        return TwoDeviceDiagnosticResult(
            category=TwoDeviceRootCause.SWITCH_PORT_PROBLEM,
            confidence_score=confidence,
            summary_title="Intermediate Switch Port or Link Discard",
            detailed_findings=findings,
            remediation_recommendations=recommendations,
            metrics_summary={"loss_pct": loss_pct, "sender_drops": s_drops, "receiver_drops": r_drops}
        )

    # 7. Default: Inconclusive / Baseline Healthy
    confidence = 85.0
    findings.append("Network performance metrics fall within normal operational boundaries. No abnormal physical corruption detected.")
    recommendations.append("Continue periodic baseline monitoring and logging.")
    return TwoDeviceDiagnosticResult(
        category=TwoDeviceRootCause.INSUFFICIENT_EVIDENCE,
        confidence_score=confidence,
        summary_title="Normal Network Operation / Insufficient Evidence of Interference",
        detailed_findings=findings,
        remediation_recommendations=recommendations,
        metrics_summary={"avg_rtt": avg_rtt, "loss_pct": loss_pct, "throughput_mbps": s_throughput}
    )
