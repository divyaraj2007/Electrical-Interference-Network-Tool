"""Analysis and Correlation package for Electrical Interference Investigation Tool."""
from .network_analysis import calculate_statistics, detect_latency_spikes, compare_periods
from .correlation import InvestigationCorrelationEngine, DiagnosticCategory, DiagnosticResult
