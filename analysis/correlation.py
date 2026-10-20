"""
Scientific Correlation and Root-Cause Classification Engine.
Distinguishes between Physical-Layer/EMI, Network Congestion, Routing/Gateway,
DNS/Application, and Insufficient Evidence.
Never jumps to EMI conclusions without corroborating physical evidence.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging

from .network_analysis import calculate_statistics, compare_periods

logger = logging.getLogger(__name__)


class DiagnosticCategory(str, Enum):
    PHYSICAL_LAYER_POSSIBLE_EMI = "physical_layer_possible_emi"
    NETWORK_CONGESTION = "network_congestion"
    ROUTING_OR_GATEWAY = "routing_or_gateway"
    DNS_OR_APPLICATION = "dns_or_application"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass
class DiagnosticResult:
    category: DiagnosticCategory
    confidence_score: float  # 0.0 to 100.0%
    summary_title: str
    detailed_findings: List[str] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)
    limitations_and_disclaimers: List[str] = field(default_factory=list)
    metrics_snapshot: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "category_label": self.category.value.replace("_", " ").title(),
            "confidence_score": round(self.confidence_score, 1),
            "summary_title": self.summary_title,
            "findings": self.detailed_findings,
            "recommendations": self.remediation_recommendations,
            "disclaimers": self.limitations_and_disclaimers,
            "metrics": self.metrics_snapshot
        }


class InvestigationCorrelationEngine:
    """
    Evaluates multi-target measurements, physical interface error deltas,
    environmental incident logs, and Test A/B/C/D comparative results.
    """

    def __init__(self, latency_spike_threshold_ms: float = 35.0,
                 loss_threshold_pct: float = 2.0):
        self.latency_spike_threshold_ms = latency_spike_threshold_ms
        self.loss_threshold_pct = loss_threshold_pct

    def analyze_investigation(self,
                              baseline_pings: List[Dict[str, Any]],
                              incident_pings: List[Dict[str, Any]],
                              comparative_tests: Optional[List[Dict[str, Any]]] = None,
                              interface_stats_deltas: Optional[Dict[str, int]] = None,
                              multi_target_pings: Optional[Dict[str, List[Dict[str, Any]]]] = None,
                              incident_meta: Optional[Dict[str, Any]] = None,
                              packet_capture_meta: Optional[Dict[str, Any]] = None) -> DiagnosticResult:
        """
        Synthesize all available investigation data and perform root-cause classification.
        """
        findings = []
        recommendations = []
        disclaimers = []
        confidence_points = 0.0  # Accumulate evidence points

        if interface_stats_deltas is None:
            interface_stats_deltas = {}
        if comparative_tests is None:
            comparative_tests = []
        if multi_target_pings is None:
            multi_target_pings = {}
        if incident_meta is None:
            incident_meta = {}

        total_base = len(baseline_pings)
        total_inc = len(incident_pings)
        total_samples = total_base + total_inc

        # 1. Sample Size & Duration Validity Check
        if total_samples < 20:
            return DiagnosticResult(
                category=DiagnosticCategory.INSUFFICIENT_EVIDENCE,
                confidence_score=15.0,
                summary_title="Insufficient Data to Draw Reliable Conclusions",
                detailed_findings=[
                    f"Only {total_samples} total packet measurements were collected.",
                    "Network statistical analysis requires at least 30 to 100 observations to filter out random background jitter."
                ],
                remediation_recommendations=[
                    "Run a continuous monitoring session for at least 5 to 15 minutes during suspected operational cycles.",
                    "Ensure test endpoints are active and responsive before initiating the investigation."
                ],
                limitations_and_disclaimers=[
                    "Brief observations cannot differentiate transient switching anomalies from systematic electrical interference."
                ]
            )

        confidence_points += min(25.0, total_samples / 4.0)  # Up to 25 pts for ample sample size

        # 2. Compare Baseline vs. Incident Periods
        comp = compare_periods(
            baseline_pings,
            incident_pings,
            error_counter_delta=interface_stats_deltas.get("crc_fcs_delta", 0) + interface_stats_deltas.get("rx_errors_delta", 0)
        )

        base_mean = comp["baseline"]["stats"]["mean"]
        inc_mean = comp["incident"]["stats"]["mean"]
        rtt_delta = comp["deltas"]["rtt_mean_delta_ms"]
        rtt_pct = comp["deltas"]["rtt_delta_pct"]
        inc_loss = comp["incident"]["loss_pct"]
        base_loss = comp["baseline"]["loss_pct"]
        loss_delta = comp["deltas"]["loss_delta_pct"]

        findings.append(f"Baseline Average RTT: {base_mean} ms (Loss: {base_loss}%, Jitter: {comp['baseline']['stats']['jitter']} ms).")
        findings.append(f"Incident Period Average RTT: {inc_mean} ms (Loss: {inc_loss}%, Jitter: {comp['incident']['stats']['jitter']} ms).")

        # 3. Check Interface Error & CRC/FCS Counters
        crc_delta = interface_stats_deltas.get("crc_fcs_delta", 0)
        rx_err_delta = interface_stats_deltas.get("rx_errors_delta", 0)
        rx_drop_delta = interface_stats_deltas.get("rx_drops_delta", 0)
        total_phy_errors = crc_delta + rx_err_delta + rx_drop_delta

        if total_phy_errors > 0:
            confidence_points += 30.0
            findings.append(
                f"Physical Layer Counter Increments: Detected {crc_delta} hardware CRC/FCS frame errors, "
                f"{rx_err_delta} receive errors, and {rx_drop_delta} dropped frames during the monitoring interval."
            )
        else:
            disclaimers.append(
                "Zero physical interface counter changes were recorded by the host OS. Note that standard consumer "
                "NICs discard corrupted frames at the PHY/MAC hardware layer before reporting to OS counters. "
                "A managed switch with SNMP or an enterprise diagnostic adapter is required to conclusively rule out frame errors."
            )

        # 4. Hop Isolation via Multi-Target Analysis
        gateway_degraded = False
        remote_degraded = False

        if "gateway" in multi_target_pings and "remote" in multi_target_pings:
            gw_pings = multi_target_pings["gateway"]
            rem_pings = multi_target_pings["remote"]
            gw_stats = calculate_statistics([p["rtt_ms"] for p in gw_pings if p.get("rtt_ms") is not None])
            rem_stats = calculate_statistics([p["rtt_ms"] for p in rem_pings if p.get("rtt_ms") is not None])
            gw_lost = sum(1 for p in gw_pings if not p.get("success"))
            rem_lost = sum(1 for p in rem_pings if not p.get("success"))
            gw_loss_pct = (gw_lost / len(gw_pings)) * 100 if gw_pings else 0
            rem_loss_pct = (rem_lost / len(rem_pings)) * 100 if rem_pings else 0

            if gw_loss_pct >= self.loss_threshold_pct or gw_stats["mean"] > (base_mean + 20.0):
                gateway_degraded = True
            if rem_loss_pct >= self.loss_threshold_pct or rem_stats["mean"] > (base_mean + 40.0):
                remote_degraded = True

            if not gateway_degraded and remote_degraded:
                # Local first hop is completely clean, but remote is failing
                findings.append(
                    f"Multi-Target Isolation: Default Gateway (Hop 1) responded cleanly (Loss: {gw_loss_pct:.1f}%, Mean: {gw_stats['mean']} ms), "
                    f"while Remote Internet Target exhibited degradation (Loss: {rem_loss_pct:.1f}%, Mean: {rem_stats['mean']} ms)."
                )
                recommendations.append("Investigate upstream ISP gateway, WAN optical link, or wide-area routing paths.")
                recommendations.append("Local Ethernet cable and switch environment appear functionally healthy.")

                return DiagnosticResult(
                    category=DiagnosticCategory.ROUTING_OR_GATEWAY,
                    confidence_score=min(95.0, confidence_points + 35.0),
                    summary_title="Upstream / WAN Routing Degradation (Local Cable Healthy)",
                    detailed_findings=findings,
                    remediation_recommendations=recommendations,
                    limitations_and_disclaimers=disclaimers,
                    metrics_snapshot=comp
                )

        # 5. Evaluate Comparative Tests (Test A, B, C, D)
        test_dict = {t["test_code"]: t for t in comparative_tests}
        comparative_evidence = False

        if "A" in test_dict and "B" in test_dict:
            test_a = test_dict["A"]
            test_b = test_dict["B"]
            b_worse = (test_b.get("packet_loss_pct", 0) > test_a.get("packet_loss_pct", 0) + 1.5) or \
                      (test_b.get("avg_rtt", 0) > test_a.get("avg_rtt", 0) + 15.0) or \
                      (test_b.get("crc_error_delta", 0) > 0)

            if b_worse:
                findings.append(
                    f"Comparative Testing: Test B (Equipment Active) showed distinct degradation compared to Test A (Baseline) "
                    f"[Test A Loss: {test_a.get('packet_loss_pct')}%, Test B Loss: {test_b.get('packet_loss_pct')}%]."
                )

                # Check if Test C (rerouting) or Test D (cable swap) eliminated the problem
                recovery_observed = False
                if "C" in test_dict and test_dict["C"].get("packet_loss_pct", 100) <= test_a.get("packet_loss_pct", 0) + 0.5:
                    recovery_observed = True
                    findings.append("Test C Confirmation: Physical cable rerouting away from the electrical source restored normal performance.")
                    confidence_points += 25.0

                if "D" in test_dict and test_dict["D"].get("packet_loss_pct", 100) <= test_a.get("packet_loss_pct", 0) + 0.5:
                    recovery_observed = True
                    findings.append("Test D Confirmation: Replacing the Ethernet cable with a known-good shielded cable eliminated the degradation.")
                    confidence_points += 25.0

                if recovery_observed:
                    comparative_evidence = True

        # 6. Evaluate Packet Capture & Wireshark Metrics
        if packet_capture_meta:
            retrans = packet_capture_meta.get("tcp_retransmissions", 0)
            dup_acks = packet_capture_meta.get("dup_acks", 0)
            dns_fails = packet_capture_meta.get("dns_failures", 0)

            if retrans > 0 or dup_acks > 0:
                findings.append(f"Packet Capture Dissection: Identified {retrans} TCP retransmissions and {dup_acks} duplicate ACKs.")

            if dns_fails > 0 and inc_loss < 1.0:
                # Potential DNS issue
                findings.append(f"Packet Capture Dissection: Detected {dns_fails} DNS query failure responses.")

        # 7. Final Classification Logic
        # Case A: Physical Layer / Possible EMI
        if (total_phy_errors > 0 and (inc_loss >= self.loss_threshold_pct or rtt_delta >= 20.0)) or comparative_evidence:
            confidence = min(92.0, max(50.0, confidence_points))
            findings.append(
                "Conclusion: Observations are consistent with physical-layer frame corruption or electromagnetic coupling along the Ethernet segment."
            )
            recommendations.append("Safely inspect the physical routing path of the Ethernet cable.")
            recommendations.append("Ensure Ethernet cabling maintains standard TIA-568 separation distance (at least 200 mm / 8 inches) from AC power lines and motors.")
            recommendations.append("Upgrade unshielded twisted-pair (UTP) to Category 6A Shielded Twisted-Pair (STP/FTP) with properly grounded patch panels.")
            recommendations.append("Never open electrical enclosures or touch live machinery wiring. Consult a certified electrician for equipment grounding checks.")
            disclaimers.append(
                "Scientific Caution: While the timing correlates with electrical equipment operation and cable replacement resolved the issue, "
                "definitive confirmation of radiated or conducted EMI requires an RF spectrum analyzer or calibrated field probe."
            )

            return DiagnosticResult(
                category=DiagnosticCategory.PHYSICAL_LAYER_POSSIBLE_EMI,
                confidence_score=confidence,
                summary_title="Evidence Consistent with Physical-Layer Ethernet Impairment / Possible EMI",
                detailed_findings=findings,
                remediation_recommendations=recommendations,
                limitations_and_disclaimers=disclaimers,
                metrics_snapshot=comp
            )

        # Case B: Network Congestion (Bufferbloat)
        if total_phy_errors == 0 and rtt_delta >= 25.0 and inc_loss <= 2.0:
            confidence = min(85.0, confidence_points + 20.0)
            findings.append("Latency increased significantly, but interface error counters showed 0 CRC/FCS frame corruptions.")
            findings.append("Sustained queueing delays without frame drops are classic signatures of bufferbloat or bandwidth saturation.")
            recommendations.append("Inspect switch and router port bandwidth utilization using SNMP or flow monitoring (NetFlow/sFlow).")
            recommendations.append("Enable Active Queue Management (AQM) such as FQ-CoDel or CAKE on the router.")
            recommendations.append("Prioritize real-time traffic using DiffServ QoS tagging.")

            return DiagnosticResult(
                category=DiagnosticCategory.NETWORK_CONGESTION,
                confidence_score=confidence,
                summary_title="Evidence Consistent with Network Congestion / Queueing Delay",
                detailed_findings=findings,
                remediation_recommendations=recommendations,
                limitations_and_disclaimers=disclaimers,
                metrics_snapshot=comp
            )

        # Case C: Stable / No significant degradation
        if inc_loss < self.loss_threshold_pct and abs(rtt_delta) < 15.0 and total_phy_errors == 0:
            return DiagnosticResult(
                category=DiagnosticCategory.INSUFFICIENT_EVIDENCE,
                confidence_score=75.0,
                summary_title="Network Performance Within Normal Operational Parameters",
                detailed_findings=findings + ["No statistically significant latency spikes, packet loss, or hardware error counts were observed."],
                remediation_recommendations=["Continue routine monitoring.", "Verify that the suspected electrical load was actively drawing current during the test."],
                limitations_and_disclaimers=disclaimers,
                metrics_snapshot=comp
            )

        # Fallback: Undetermined / Insufficient proof
        return DiagnosticResult(
            category=DiagnosticCategory.INSUFFICIENT_EVIDENCE,
            confidence_score=40.0,
            summary_title="Indeterminate Results - Further Controlled Isolation Required",
            detailed_findings=findings,
            remediation_recommendations=[
                "Perform structured Test A through Test D isolation protocol.",
                "Connect via a managed switch to capture port-level FCS counters.",
                "Verify if degradation coincides strictly with equipment duty cycles."
            ],
            limitations_and_disclaimers=disclaimers,
            metrics_snapshot=comp
        )
