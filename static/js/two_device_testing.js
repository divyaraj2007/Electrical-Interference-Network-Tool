/**
 * Two-Device Testing Interactive Controller & Live Telemetry Stream
 * Manages test execution, live charts, comparative telemetry, and root-cause diagnosis.
 */

let rttChart = null;
let throughputChart = null;
let lossChart = null;
let errorChart = null;

let currentRunningTestId = null;
let testPollInterval = null;
let testElapsedSec = 0;
let registeredDevicesMap = {};

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    initDeviceSelection();
    initTestControls();
    initRealTimeTelemetryStream();
    loadDeviceMetadata();
});

/**
 * Initialize Chart.js instances with Dark Theme styling
 */
function initCharts() {
    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        plugins: {
            legend: { labels: { color: "#cbd5e1", font: { size: 10 } } }
        },
        scales: {
            x: {
                grid: { color: "rgba(255, 255, 255, 0.07)" },
                ticks: { color: "#94a3b8", font: { size: 9 }, maxTicksLimit: 12 }
            },
            y: {
                grid: { color: "rgba(255, 255, 255, 0.07)" },
                ticks: { color: "#94a3b8", font: { size: 9 } },
                beginAtZero: true
            }
        }
    };

    // 1. RTT & Jitter Chart
    const ctxRtt = document.getElementById("chart-two-dev-rtt")?.getContext("2d");
    if (ctxRtt) {
        rttChart = new Chart(ctxRtt, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "RTT (ms)",
                        borderColor: "#38bdf8",
                        backgroundColor: "rgba(56, 189, 248, 0.15)",
                        borderWidth: 2,
                        tension: 0.2,
                        fill: true,
                        data: []
                    },
                    {
                        label: "Jitter RFC 3550 (ms)",
                        borderColor: "#fbbf24",
                        borderWidth: 1.5,
                        borderDash: [4, 4],
                        tension: 0.2,
                        fill: false,
                        data: []
                    }
                ]
            },
            options: chartDefaults
        });
    }

    // 2. Throughput Chart
    const ctxThroughput = document.getElementById("chart-two-dev-throughput")?.getContext("2d");
    if (ctxThroughput) {
        throughputChart = new Chart(ctxThroughput, {
            type: "bar",
            data: {
                labels: ["Upload (Sender Tx)", "Download (Receiver Rx)"],
                datasets: [
                    {
                        label: "Throughput (Mbps)",
                        backgroundColor: ["#3b82f6", "#10b981"],
                        borderWidth: 0,
                        borderRadius: 4,
                        data: [0, 0]
                    }
                ]
            },
            options: {
                ...chartDefaults,
                scales: {
                    ...chartDefaults.scales,
                    y: { ...chartDefaults.scales.y, title: { display: true, text: "Mbps", color: "#94a3b8" } }
                }
            }
        });
    }

    // 3. Packet Loss Chart
    const ctxLoss = document.getElementById("chart-two-dev-loss")?.getContext("2d");
    if (ctxLoss) {
        lossChart = new Chart(ctxLoss, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Packet Loss (%)",
                        borderColor: "#ef4444",
                        backgroundColor: "rgba(239, 68, 68, 0.2)",
                        borderWidth: 2,
                        stepped: true,
                        fill: true,
                        data: []
                    }
                ]
            },
            options: {
                ...chartDefaults,
                scales: {
                    ...chartDefaults.scales,
                    y: { ...chartDefaults.scales.y, max: 100 }
                }
            }
        });
    }

    // 4. Interface Error & CRC Delta Chart
    const ctxErr = document.getElementById("chart-two-dev-errors")?.getContext("2d");
    if (ctxErr) {
        errorChart = new Chart(ctxErr, {
            type: "bar",
            data: {
                labels: ["Sender Errors", "Receiver Errors", "Sender CRC", "Receiver CRC"],
                datasets: [
                    {
                        label: "Counter Deltas",
                        backgroundColor: ["#f97316", "#fb923c", "#eab308", "#facc15"],
                        borderWidth: 0,
                        borderRadius: 4,
                        data: [0, 0, 0, 0]
                    }
                ]
            },
            options: chartDefaults
        });
    }
}

/**
 * Fetch and store registered device metadata for live card rendering
 */
async function loadDeviceMetadata() {
    try {
        const res = await fetch("/api/devices");
        const data = await res.json();
        if (data.devices) {
            registeredDevicesMap = {};
            data.devices.forEach((d) => {
                registeredDevicesMap[d.device_id] = d;
            });
            updateSelectedDeviceCards();
        }
    } catch (e) {
        console.error("Device fetch failed:", e);
    }
}

/**
 * Handle Sender and Receiver dropdown changes
 */
function initDeviceSelection() {
    const selSender = document.getElementById("sel-sender-device");
    const selReceiver = document.getElementById("sel-receiver-device");

    if (selSender && selSender.options.length > 1 && !selSender.value) {
        selSender.selectedIndex = 1;
    }
    if (selReceiver && selReceiver.options.length > 1 && !selReceiver.value) {
        selReceiver.selectedIndex = 1;
    }

    selSender?.addEventListener("change", updateSelectedDeviceCards);
    selReceiver?.addEventListener("change", updateSelectedDeviceCards);

    // Auto-load latest test if present in table
    const firstTestRow = document.querySelector("#tests-history-table tbody tr[data-test-id]");
    if (firstTestRow) {
        const latestId = firstTestRow.dataset.testId;
        loadAndRenderTestResults(latestId);
    }
}

function updateSelectedDeviceCards() {
    const sId = document.getElementById("sel-sender-device")?.value;
    const rId = document.getElementById("sel-receiver-device")?.value;

    const sDev = registeredDevicesMap[sId];
    if (sDev) {
        document.getElementById("sender-display-name").textContent = sDev.hostname || sDev.device_id;
        document.getElementById("sender-display-id").textContent = sDev.device_id;
        document.getElementById("sender-ip").textContent = sDev.ip_address || "127.0.0.1";
        document.getElementById("sender-nic").textContent = `${sDev.active_interface || "eth0"} (${sDev.link_speed_mbps}M)`;
        document.getElementById("sender-cpu").textContent = `${(sDev.cpu_pct || 0).toFixed(1)}%`;
        document.getElementById("sender-crc").textContent = sDev.crc_supported ? `${sDev.crc_fcs_errors || 0}` : "N/A";
        document.getElementById("sender-os").textContent = sDev.os_info || "Windows / Linux";
        document.getElementById("sender-hb").textContent = sDev.last_heartbeat || "Never";

        const pill = document.getElementById("sender-status-pill");
        if (pill) {
            pill.className = `badge fs-8 ${sDev.status === "online" ? "bg-success" : (sDev.status === "testing" ? "bg-warning text-dark" : "bg-secondary")}`;
            pill.innerHTML = `<i class="bi bi-circle-fill me-1 small"></i> ${sDev.status.toUpperCase()}`;
        }
    }

    const rDev = registeredDevicesMap[rId];
    if (rDev) {
        document.getElementById("receiver-display-name").textContent = rDev.hostname || rDev.device_id;
        document.getElementById("receiver-display-id").textContent = rDev.device_id;
        document.getElementById("receiver-ip").textContent = rDev.ip_address || "127.0.0.1";
        document.getElementById("receiver-nic").textContent = `${rDev.active_interface || "eth0"} (${rDev.link_speed_mbps}M)`;
        document.getElementById("receiver-cpu").textContent = `${(rDev.cpu_pct || 0).toFixed(1)}%`;
        document.getElementById("receiver-crc").textContent = rDev.crc_supported ? `${rDev.crc_fcs_errors || 0}` : "N/A";
        document.getElementById("receiver-os").textContent = rDev.os_info || "Windows / Linux";
        document.getElementById("receiver-hb").textContent = rDev.last_heartbeat || "Never";

        const pill = document.getElementById("receiver-status-pill");
        if (pill) {
            pill.className = `badge fs-8 ${rDev.status === "online" ? "bg-success" : (rDev.status === "testing" ? "bg-warning text-dark" : "bg-secondary")}`;
            pill.innerHTML = `<i class="bi bi-circle-fill me-1 small"></i> ${rDev.status.toUpperCase()}`;
        }
    }
}

/**
 * Configure Test Actions: Preflight, Start, Stop, and Benchmark Seeder
 */
function initTestControls() {
    // 1. Preflight Check
    document.getElementById("btn-preflight-check")?.addEventListener("click", async () => {
        const sId = document.getElementById("sel-sender-device").value;
        const rId = document.getElementById("sel-receiver-device").value;

        if (!sId || !rId) {
            alert("Please select both a Sender device and a Receiver device first.");
            return;
        }

        const alertBox = document.getElementById("preflight-alert");
        const msgEl = document.getElementById("preflight-msg");
        alertBox.classList.remove("d-none", "alert-success", "alert-danger");
        alertBox.classList.add("alert-info");
        msgEl.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Verifying end-to-end connectivity between ${sId} and ${rId}...`;

        try {
            const res = await fetch("/api/two-device/tests/preflight", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sender_device_id: sId, receiver_device_id: rId })
            });
            const data = await res.json();
            if (data.success && data.reachable) {
                alertBox.classList.replace("alert-info", "alert-success");
                msgEl.innerHTML = `<i class="bi bi-check-circle-fill me-2 text-success"></i>Pre-flight verification passed! Latency: ${data.rtt_ms.toFixed(2)} ms. Sender and Receiver are synchronized and ready.`;
            } else {
                alertBox.classList.replace("alert-info", "alert-warning");
                msgEl.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2 text-warning"></i>${data.message || "Connectivity check failed or node offline."}`;
            }
        } catch (err) {
            alertBox.classList.replace("alert-info", "alert-danger");
            msgEl.innerHTML = `<i class="bi bi-x-circle-fill me-2 text-danger"></i>Pre-flight error: ${err.message}`;
        }
    });

    // 2. Start Coordinated Test
    document.getElementById("btn-start-two-test")?.addEventListener("click", async () => {
        const sId = document.getElementById("sel-sender-device").value;
        const rId = document.getElementById("sel-receiver-device").value;

        if (!sId || !rId) {
            alert("Please select both Sender and Receiver devices.");
            return;
        }

        // Collect modes
        const modes = [];
        document.querySelectorAll("#form-two-device-test input[type='checkbox']:checked").forEach((chk) => {
            modes.push(chk.value);
        });

        const duration = parseInt(document.getElementById("inp-duration").value) || 30;
        const pktSize = parseInt(document.getElementById("inp-pkt-size").value) || 64;
        const interval = parseFloat(document.getElementById("inp-interval").value) || 0.5;
        const direction = document.getElementById("sel-direction").value;
        const eqState = document.getElementById("sel-eq-state").value;
        const incId = document.getElementById("sel-incident").value || null;
        const name = document.getElementById("inp-test-name").value.trim();

        const payload = {
            sender_device_id: sId,
            receiver_device_id: rId,
            test_modes: modes,
            direction: direction,
            duration_sec: duration,
            packet_size_bytes: pktSize,
            interval_sec: interval,
            equipment_state: eqState,
            incident_id: incId ? parseInt(incId) : null,
            name: name || undefined
        };

        try {
            const res = await fetch("/api/two-device/tests/create", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.success) {
                currentRunningTestId = data.test_id;
                document.getElementById("btn-start-two-test").disabled = true;
                document.getElementById("btn-stop-two-test").disabled = false;

                // Show progress bar
                showTestProgress(duration);
                startTestPolling(data.test_id, duration);
            } else {
                alert("Failed to start test: " + data.error);
            }
        } catch (err) {
            alert("Error initiating test: " + err.message);
        }
    });

    // 3. Stop Test
    document.getElementById("btn-stop-two-test")?.addEventListener("click", async () => {
        if (!currentRunningTestId) return;
        try {
            const res = await fetch(`/api/two-device/tests/${currentRunningTestId}/stop`, { method: "POST" });
            const data = await res.json();
            if (data.success) {
                stopTestPolling();
                document.getElementById("btn-start-two-test").disabled = false;
                document.getElementById("btn-stop-two-test").disabled = true;
                document.getElementById("test-progress-container").classList.add("d-none");
            }
        } catch (err) {
            console.error("Stop error:", err);
        }
    });

    // 4. Seed Two-Device Benchmark Demo
    document.getElementById("btn-seed-two-dev-demo")?.addEventListener("click", async () => {
        if (confirm("Load benchmark two-device interference demonstration (industrial VFD interference test)?")) {
            try {
                const res = await fetch("/api/two-device/demo/seed", { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    alert("Benchmark two-device dataset loaded successfully!");
                    window.location.reload();
                }
            } catch (err) {
                alert("Demo load failed: " + err.message);
            }
        }
    });

    // 5. View Test Results from History Table
    document.addEventListener("click", async (e) => {
        const btnView = e.target.closest(".btn-view-test-results");
        if (btnView) {
            const testId = btnView.dataset.testId;
            await loadAndRenderTestResults(testId);
            window.scrollTo({ top: 300, behavior: "smooth" });
        }
    });
}

/**
 * Handle progress bar animation during active test
 */
function showTestProgress(durationSec) {
    const container = document.getElementById("test-progress-container");
    const bar = document.getElementById("test-progress-bar");
    const counter = document.getElementById("test-elapsed-counter");
    container.classList.remove("d-none");

    testElapsedSec = 0;
    const intervalTimer = setInterval(() => {
        testElapsedSec++;
        const pct = Math.min(100, Math.round((testElapsedSec / durationSec) * 100));
        bar.style.width = `${pct}%`;
        const m = String(Math.floor(testElapsedSec / 60)).padStart(2, "0");
        const s = String(testElapsedSec % 60).padStart(2, "0");
        counter.textContent = `Elapsed: ${m}:${s} / ${durationSec}s`;

        if (testElapsedSec >= durationSec + 5) {
            clearInterval(intervalTimer);
        }
    }, 1000);
}

/**
 * Poll test status until completion
 */
function startTestPolling(testId, durationSec) {
    if (testPollInterval) clearInterval(testPollInterval);

    testPollInterval = setInterval(async () => {
        try {
            const res = await fetch(`/api/two-device/tests/${testId}/status`);
            const data = await res.json();
            if (data.success) {
                // If measurements are available, update live charts
                if (data.recent_measurements && data.recent_measurements.length > 0) {
                    updateChartsWithMeasurements(data.recent_measurements);
                }

                if (data.status === "completed" || data.status === "stopped" || data.status === "failed") {
                    stopTestPolling();
                    document.getElementById("btn-start-two-test").disabled = false;
                    document.getElementById("btn-stop-two-test").disabled = true;
                    document.getElementById("test-progress-container").classList.add("d-none");
                    await loadAndRenderTestResults(testId);
                }
            }
        } catch (err) {
            console.debug("Status poll exception:", err);
        }
    }, 2000);
}

function stopTestPolling() {
    if (testPollInterval) {
        clearInterval(testPollInterval);
        testPollInterval = null;
    }
}

/**
 * Load complete results for a test and populate tables and charts
 */
async function loadAndRenderTestResults(testId) {
    try {
        const res = await fetch(`/api/two-device/tests/${testId}/results`);
        const data = await res.json();
        if (!data.success) return;

        const summary = data.summary || {};
        const sRes = summary.sender || {};
        const rRes = summary.receiver || {};
        const analysis = data.analysis || {};

        const sPing = sRes.metrics?.ping || {};
        const sTcp = sRes.metrics?.tcp_throughput || {};
        const rTraffic = rRes.incoming_traffic || {};
        const sIf = sRes.interface_deltas || {};
        const rIf = rRes.interface_deltas || {};

        // Update Comparison Table
        document.getElementById("comp-s-rtt").textContent = `${(sPing.avg_rtt_ms || 0).toFixed(2)} ms`;
        document.getElementById("comp-eval-rtt").textContent = sPing.avg_rtt_ms < 10 ? "Optimal Latency" : "Elevated Latency";

        document.getElementById("comp-s-jitter").textContent = `${(sPing.jitter_ms || 0).toFixed(3)} ms`;
        document.getElementById("comp-r-jitter").textContent = `${(sTcp.jitter_ms || 0).toFixed(3)} ms`;
        document.getElementById("comp-eval-jitter").textContent = sPing.jitter_ms < 5 ? "Normal" : "Excessive Jitter";

        document.getElementById("comp-s-loss").textContent = `${(sPing.loss_pct || 0).toFixed(1)}%`;
        document.getElementById("comp-r-loss").textContent = `${(sPing.loss_pct || 0).toFixed(1)}%`;
        document.getElementById("comp-eval-loss").textContent = sPing.loss_pct === 0 ? "Zero Loss (Clean)" : `${sPing.loss_pct}% Packet Loss`;

        const sMb = sTcp.throughput_mbps || 0;
        const rMb = rTraffic.measured_throughput_mbps || sMb;
        document.getElementById("comp-s-mbps").textContent = `${sMb.toFixed(1)} Mbps`;
        document.getElementById("comp-r-mbps").textContent = `${rMb.toFixed(1)} Mbps`;
        document.getElementById("comp-eval-mbps").textContent = sMb > 500 ? "High Performance" : "Constrained / Throttled";

        document.getElementById("comp-s-retrans").textContent = sTcp.retransmissions || 0;
        document.getElementById("comp-eval-retrans").textContent = (sTcp.retransmissions || 0) === 0 ? "Clean Stream" : "TCP Retransmissions Observed";

        const sDrops = (sIf.rx_drops_delta || 0) + (sIf.tx_drops_delta || 0);
        const rDrops = (rIf.rx_drops_delta || 0) + (rIf.tx_drops_delta || 0);
        document.getElementById("comp-s-drops").textContent = `${sDrops} discards`;
        document.getElementById("comp-r-drops").textContent = `${rDrops} discards`;
        document.getElementById("comp-eval-drops").textContent = (sDrops + rDrops) === 0 ? "Zero Drops" : "NIC Discards Detected";

        const sCrcStr = sIf.crc_supported ? `${sIf.crc_delta || 0}` : "Not exposed by OS";
        const rCrcStr = rIf.crc_supported ? `${rIf.crc_delta || 0}` : "Not exposed by OS";
        document.getElementById("comp-s-crc").textContent = sCrcStr;
        document.getElementById("comp-r-crc").textContent = rCrcStr;
        document.getElementById("comp-eval-crc").textContent = (sIf.crc_delta > 0 || rIf.crc_delta > 0) ? "Physical FCS Corruption" : "Hardware Counters Clean";

        // Update Charts
        if (throughputChart) {
            throughputChart.data.datasets[0].data = [sMb, rMb];
            throughputChart.update();
            document.getElementById("throughput-latest-badge").textContent = `${sMb.toFixed(1)} Mbps`;
        }

        if (errorChart) {
            const sErr = (sIf.rx_errors_delta || 0) + (sIf.tx_errors_delta || 0);
            const rErr = (rIf.rx_errors_delta || 0) + (rIf.tx_errors_delta || 0);
            errorChart.data.datasets[0].data = [sErr, rErr, sIf.crc_delta || 0, rIf.crc_delta || 0];
            errorChart.update();
            document.getElementById("crc-latest-badge").textContent = `${(sIf.crc_delta || 0) + (rIf.crc_delta || 0)} CRC / ${(sErr + rErr)} Err`;
        }

        // Update Root Cause Diagnosis
        if (analysis) {
            const cat = analysis.category || "insufficient_evidence";
            const badge = document.getElementById("analysis-category-badge");
            badge.textContent = cat.replace(/_/g, " ").toUpperCase();
            badge.className = `badge fs-8 ${cat.includes("emi") || cat.includes("cable") ? "bg-danger" : (cat.includes("congestion") ? "bg-warning text-dark" : "bg-info text-dark")}`;

            const conf = analysis.confidence_score || 0;
            document.getElementById("analysis-confidence").textContent = `${conf.toFixed(1)}%`;
            document.getElementById("analysis-confidence-bar").style.width = `${conf}%`;

            const findingsUl = document.getElementById("analysis-findings-list");
            findingsUl.innerHTML = "";
            (analysis.findings || []).forEach((f) => {
                const li = document.createElement("li");
                li.className = "mb-1";
                li.innerHTML = `<i class="bi bi-arrow-right-circle text-info me-1"></i> ${f}`;
                findingsUl.appendChild(li);
            });

            const recsUl = document.getElementById("analysis-recommendations-list");
            recsUl.innerHTML = "";
            (analysis.recommendations || []).forEach((r) => {
                const li = document.createElement("li");
                li.className = "mb-1";
                li.innerHTML = `<i class="bi bi-shield-check text-success me-1"></i> ${r}`;
                recsUl.appendChild(li);
            });
        }
    } catch (err) {
        console.error("Result loading error:", err);
    }
}

function updateChartsWithMeasurements(measurements) {
    const rttLabels = [];
    const rttData = [];
    const jitterData = [];
    const lossLabels = [];
    const lossData = [];

    measurements.forEach((m, idx) => {
        if (m.metric_type === "ping" && m.data) {
            const timeLabel = m.timestamp.split(" ")[1] || `#${idx + 1}`;
            rttLabels.push(timeLabel);
            rttData.push(m.data.rtt_ms || m.value_numeric || 0);
            jitterData.push(m.data.jitter_ms || 0);

            lossLabels.push(timeLabel);
            lossData.push(m.data.loss ? 100 : 0);
        }
    });

    if (rttChart && rttLabels.length > 0) {
        rttChart.data.labels = rttLabels;
        rttChart.data.datasets[0].data = rttData;
        rttChart.data.datasets[1].data = jitterData;
        rttChart.update();
        const latestRtt = rttData[rttData.length - 1];
        document.getElementById("rtt-latest-badge").textContent = `${latestRtt.toFixed(2)} ms`;
    }

    if (lossChart && lossLabels.length > 0) {
        lossChart.data.labels = lossLabels;
        lossChart.data.datasets[0].data = lossData;
        lossChart.update();
    }
}

/**
 * Real-Time Telemetry Stream Handler via Server-Sent Events
 */
function initRealTimeTelemetryStream() {
    if (window.location.search.includes("static_capture=1")) {
        return; // Skip persistent SSE stream for headless screenshot capture
    }
    if (typeof EventSource !== "undefined") {
        const sse = new EventSource("/api/devices/stream");
        sse.onmessage = (event) => {
            try {
                const payload = JSON.parse(event.data);
                if (payload.devices) {
                    payload.devices.forEach((d) => {
                        registeredDevicesMap[d.device_id] = d;
                    });
                    updateSelectedDeviceCards();
                }
            } catch (e) {
                console.debug("SSE telemetry parse error:", e);
            }
        };
    }
}
