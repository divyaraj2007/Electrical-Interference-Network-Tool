/**
 * Chart.js Real-Time Telemetry Visualizer
 * Manages streaming latency graphs, jitter thresholds, packet loss ratios,
 * and physical hardware CRC/FCS counter deltas.
 */

let latencyChart = null;
let lossErrorChart = null;

const MAX_CHART_POINTS = 60;

function initCharts() {
    // 1. Latency (RTT) Chart Setup
    const ctxLatency = document.getElementById('latencyChart');
    if (ctxLatency) {
        latencyChart = new Chart(ctxLatency.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'RTT (ms)',
                        data: [],
                        borderColor: '#0dcaf0',
                        backgroundColor: 'rgba(13, 202, 240, 0.1)',
                        borderWidth: 2,
                        pointRadius: 2,
                        pointHoverRadius: 5,
                        fill: true,
                        tension: 0.25
                    },
                    {
                        label: 'Warning Threshold (75ms)',
                        data: [],
                        borderColor: 'rgba(210, 153, 34, 0.6)',
                        borderWidth: 1.5,
                        borderDash: [5, 5],
                        pointRadius: 0,
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: {
                        labels: { color: '#8b949e', font: { size: 10 } }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#8b949e', font: { size: 9 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
                        grid: { color: '#21262d' }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#8b949e', font: { size: 10 } },
                        grid: { color: '#21262d' },
                        title: { display: true, text: 'Milliseconds (ms)', color: '#8b949e', font: { size: 10 } }
                    }
                }
            }
        });
    }

    // 2. Packet Loss % & CRC Delta Dual Chart
    const ctxLoss = document.getElementById('lossErrorChart');
    if (ctxLoss) {
        lossErrorChart = new Chart(ctxLoss.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Packet Loss (%)',
                        data: [],
                        backgroundColor: 'rgba(248, 81, 73, 0.75)',
                        borderColor: '#f85149',
                        borderWidth: 1,
                        yAxisID: 'y'
                    },
                    {
                        label: 'CRC/FCS Delta',
                        data: [],
                        type: 'line',
                        borderColor: '#ffc107',
                        backgroundColor: '#ffc107',
                        borderWidth: 2,
                        pointRadius: 3,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: {
                    legend: {
                        labels: { color: '#8b949e', font: { size: 10 } }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#8b949e', font: { size: 9 }, maxTicksLimit: 6 },
                        grid: { color: '#21262d' }
                    },
                    y: {
                        type: 'linear',
                        position: 'left',
                        beginAtZero: true,
                        max: 100,
                        ticks: { color: '#8b949e', font: { size: 9 } },
                        grid: { color: '#21262d' },
                        title: { display: true, text: 'Loss %', color: '#f85149', font: { size: 9 } }
                    },
                    y1: {
                        type: 'linear',
                        position: 'right',
                        beginAtZero: true,
                        grid: { drawOnChartArea: false },
                        ticks: { color: '#ffc107', font: { size: 9 }, stepSize: 1 },
                        title: { display: true, text: 'CRC Delta', color: '#ffc107', font: { size: 9 } }
                    }
                }
            }
        });
    }
}

function updateChartsWithData(measurements, interfaceStats) {
    if (!measurements || measurements.length === 0) return;

    // Use last N measurements
    const slice = measurements.slice(-MAX_CHART_POINTS);
    const labels = slice.map(m => m.timestamp ? m.timestamp.split(' ')[1] : '');
    const rtts = slice.map(m => m.rtt_ms !== null ? m.rtt_ms : null);
    const thresholds = slice.map(() => 75.0);

    if (latencyChart) {
        latencyChart.data.labels = labels;
        latencyChart.data.datasets[0].data = rtts;
        latencyChart.data.datasets[1].data = thresholds;
        latencyChart.update('none');

        const countEl = document.getElementById('chart-point-count');
        if (countEl) countEl.textContent = `${slice.length} points`;
    }

    if (lossErrorChart) {
        // Compute loss % over rolling 5-packet buckets
        const lossData = slice.map(m => (!m.success || m.timeout) ? 100.0 : 0.0);
        const crcDeltas = slice.map(() => (interfaceStats && interfaceStats.crc_fcs_delta) ? interfaceStats.crc_fcs_delta : 0);

        lossErrorChart.data.labels = labels;
        lossErrorChart.data.datasets[0].data = lossData;
        lossErrorChart.data.datasets[1].data = crcDeltas;
        lossErrorChart.update('none');
    }
}

document.addEventListener('DOMContentLoaded', initCharts);
