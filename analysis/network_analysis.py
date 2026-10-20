"""
Statistical Network Analysis Module.
Performs rigorous statistical calculations on round-trip times (RTT), jitter,
latency spikes, packet loss ratios, and comparative baseline analysis.
"""

import math
from typing import List, Dict, Any, Optional, Tuple


def calculate_statistics(rtt_values: List[float]) -> Dict[str, Any]:
    """
    Calculate comprehensive statistical descriptors for a list of RTT measurements.
    Filters out None and negative values.
    """
    valid = [float(x) for x in rtt_values if x is not None and x >= 0]
    count = len(valid)

    if count == 0:
        return {
            "count": 0,
            "mean": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "std_dev": 0.0,
            "jitter": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "iqr": 0.0
        }

    sorted_vals = sorted(valid)
    mean_val = sum(sorted_vals) / count

    # Variance and Standard Deviation (Jitter)
    if count > 1:
        variance = sum((x - mean_val) ** 2 for x in sorted_vals) / (count - 1)
        std_dev = math.sqrt(variance)
    else:
        variance = 0.0
        std_dev = 0.0

    # Median (50th percentile)
    if count % 2 == 1:
        median_val = sorted_vals[count // 2]
    else:
        median_val = (sorted_vals[(count // 2) - 1] + sorted_vals[count // 2]) / 2.0

    # Percentiles helper
    def get_percentile(p: float) -> float:
        k = (count - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_vals[int(k)]
        d0 = sorted_vals[int(f)] * (c - k)
        d1 = sorted_vals[int(c)] * (k - f)
        return d0 + d1

    p25 = get_percentile(0.25)
    p75 = get_percentile(0.75)
    iqr = p75 - p25
    p95 = get_percentile(0.95)
    p99 = get_percentile(0.99)

    # RFC 3550 Interarrival Jitter approximation across sequential readings
    consecutive_diffs = [abs(sorted_vals[i] - sorted_vals[i - 1]) for i in range(1, count)]
    rfc_jitter = sum(consecutive_diffs) / len(consecutive_diffs) if consecutive_diffs else 0.0

    return {
        "count": count,
        "mean": round(mean_val, 2),
        "median": round(median_val, 2),
        "min": round(sorted_vals[0], 2),
        "max": round(sorted_vals[-1], 2),
        "std_dev": round(std_dev, 2),
        "jitter": round(rfc_jitter, 2),
        "p95": round(p95, 2),
        "p99": round(p99, 2),
        "iqr": round(iqr, 2)
    }


def detect_latency_spikes(measurements: List[Dict[str, Any]],
                          std_dev_multiplier: float = 2.5,
                          absolute_min_spike_ms: float = 30.0) -> List[Dict[str, Any]]:
    """
    Identify unusual latency spikes using dynamic statistical thresholds.
    A measurement is flagged if RTT > (Mean + multiplier * StdDev) and RTT > absolute_min_spike_ms.
    """
    valid_rtts = [m["rtt_ms"] for m in measurements if m.get("rtt_ms") is not None]
    if len(valid_rtts) < 5:
        return []

    stats = calculate_statistics(valid_rtts)
    threshold = max(stats["mean"] + (std_dev_multiplier * stats["std_dev"]), stats["mean"] + absolute_min_spike_ms)

    spikes = []
    for m in measurements:
        rtt = m.get("rtt_ms")
        if rtt is not None and rtt >= threshold:
            spike_item = dict(m)
            spike_item["deviation_from_mean"] = round(rtt - stats["mean"], 2)
            spike_item["threshold_used"] = round(threshold, 2)
            spikes.append(spike_item)

    return spikes


def compare_periods(baseline_measurements: List[Dict[str, Any]],
                    incident_measurements: List[Dict[str, Any]],
                    error_counter_delta: int = 0) -> Dict[str, Any]:
    """
    Scientifically compare a baseline observation period against an incident observation period.
    Returns metrics comparison, delta percentages, and significance assessment.
    """
    # Baseline stats
    base_rtts = [m["rtt_ms"] for m in baseline_measurements if m.get("rtt_ms") is not None]
    base_total = len(baseline_measurements)
    base_lost = sum(1 for m in baseline_measurements if not m.get("success") or m.get("timeout"))
    base_loss_pct = round((base_lost / base_total) * 100.0, 2) if base_total > 0 else 0.0
    base_stats = calculate_statistics(base_rtts)

    # Incident stats
    inc_rtts = [m["rtt_ms"] for m in incident_measurements if m.get("rtt_ms") is not None]
    inc_total = len(incident_measurements)
    inc_lost = sum(1 for m in incident_measurements if not m.get("success") or m.get("timeout"))
    inc_loss_pct = round((inc_lost / inc_total) * 100.0, 2) if inc_total > 0 else 0.0
    inc_stats = calculate_statistics(inc_rtts)

    # Latency delta
    if base_stats["mean"] > 0:
        rtt_delta_pct = round(((inc_stats["mean"] - base_stats["mean"]) / base_stats["mean"]) * 100.0, 2)
    else:
        rtt_delta_pct = 0.0

    loss_delta_pct = round(inc_loss_pct - base_loss_pct, 2)
    jitter_delta = round(inc_stats["jitter"] - base_stats["jitter"], 2)

    # Check for degradation
    latency_degradation = inc_stats["mean"] > (base_stats["mean"] + 15.0) or rtt_delta_pct >= 40.0
    loss_degradation = inc_loss_pct >= 2.0 and loss_delta_pct >= 2.0
    error_counter_active = error_counter_delta > 0

    return {
        "baseline": {
            "total_packets": base_total,
            "lost_packets": base_lost,
            "loss_pct": base_loss_pct,
            "stats": base_stats
        },
        "incident": {
            "total_packets": inc_total,
            "lost_packets": inc_lost,
            "loss_pct": inc_loss_pct,
            "stats": inc_stats
        },
        "deltas": {
            "rtt_mean_delta_ms": round(inc_stats["mean"] - base_stats["mean"], 2),
            "rtt_delta_pct": rtt_delta_pct,
            "loss_delta_pct": loss_delta_pct,
            "jitter_delta_ms": jitter_delta,
            "error_counter_delta": error_counter_delta
        },
        "flags": {
            "latency_degraded": latency_degradation,
            "loss_degraded": loss_degradation,
            "interface_errors_present": error_counter_active
        }
    }
