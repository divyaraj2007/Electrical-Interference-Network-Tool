/**
 * Live Dashboard Controller
 * Real-time polling, Start/Stop monitoring, KPI element updates,
 * multi-target hop telemetry, and TShark capture controls.
 */

let pollIntervalId = null;
let isCurrentlyMonitoring = false;

document.addEventListener('DOMContentLoaded', () => {
    // Bind UI elements
    const btnStart = document.getElementById('btn-start-monitor');
    const btnStop = document.getElementById('btn-stop-monitor');
    const chkMultiTarget = document.getElementById('chk-multi-target');
    const multiTargetConfig = document.getElementById('multi-target-config');
    const durationSelect = document.getElementById('duration-select');

    // Multi-target toggle
    chkMultiTarget?.addEventListener('change', () => {
        if (chkMultiTarget.checked) {
            multiTargetConfig.classList.remove('d-none');
        } else {
            multiTargetConfig.classList.add('d-none');
        }
    });

    // Start Monitoring button handler
    btnStart?.addEventListener('click', async () => {
        const targetIp = document.getElementById('target-ip').value.trim();
        const iface = document.getElementById('interface-select').value;
        const interval = parseFloat(document.getElementById('interval-sec').value);
        const timeout = parseFloat(document.getElementById('timeout-sec').value);
        const durationVal = durationSelect.value;
        const isMulti = chkMultiTarget?.checked || false;

        if (!targetIp) {
            alert('Please enter a valid target IP address or hostname.');
            return;
        }

        const payload = {
            target: targetIp,
            interface_name: iface,
            interval_sec: interval,
            timeout_sec: timeout,
            mode: isMulti ? 'multi_target' : (durationVal === 'continuous' ? 'continuous' : 'single'),
            duration_sec: durationVal === 'continuous' ? 3600 : parseInt(durationVal),
            preset_11h: durationVal === '39600'
        };

        if (isMulti) {
            payload.gateway = document.getElementById('target-gateway').value.trim();
            payload.local_peer = document.getElementById('target-peer').value.trim();
            payload.dns_server = document.getElementById('target-dns').value.trim();
            payload.internet_dest = document.getElementById('target-remote').value.trim();
        }

        btnStart.disabled = true;
        btnStart.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Starting...';

        try {
            const res = await fetch('/api/monitoring/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            if (!res.ok || !data.success) {
                alert('Failed to start monitoring: ' + (data.error || 'Unknown error'));
                btnStart.disabled = false;
                btnStart.innerHTML = '<i class="bi bi-play-fill me-1"></i> Start Monitoring';
                return;
            }

            // Successfully started
            isCurrentlyMonitoring = true;
            btnStart.disabled = true;
            btnStart.innerHTML = '<i class="bi bi-play-fill me-1"></i> Start Monitoring';
            btnStop.disabled = false;
            startPolling();
        } catch (err) {
            alert('Error communicating with backend: ' + err);
            btnStart.disabled = false;
            btnStart.innerHTML = '<i class="bi bi-play-fill me-1"></i> Start Monitoring';
        }
    });

    // Stop Monitoring button handler
    btnStop?.addEventListener('click', async () => {
        btnStop.disabled = true;
        btnStop.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Stopping...';

        try {
            const res = await fetch('/api/monitoring/stop', { method: 'POST' });
            const data = await res.json();

            btnStop.disabled = true;
            btnStop.innerHTML = '<i class="bi bi-stop-fill me-1"></i> Stop';
            btnStart.disabled = false;
            isCurrentlyMonitoring = false;
        } catch (err) {
            alert('Error stopping monitoring: ' + err);
            btnStop.disabled = false;
            btnStop.innerHTML = '<i class="bi bi-stop-fill me-1"></i> Stop';
        }
    });

    // Packet capture handlers
    const btnStartPcap = document.getElementById('btn-start-pcap');
    const btnStopPcap = document.getElementById('btn-stop-pcap');

    btnStartPcap?.addEventListener('click', async () => {
        const iface = document.getElementById('pcap-interface').value;
        const dur = parseInt(document.getElementById('pcap-duration').value);

        btnStartPcap.disabled = true;
        btnStartPcap.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Capturing...';

        try {
            const res = await fetch('/api/captures/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface_id: iface, duration_sec: dur })
            });
            const data = await res.json();
            if (!data.success) {
                alert('Capture error: ' + (data.error || 'Failed to start'));
                btnStartPcap.disabled = false;
                btnStartPcap.innerHTML = '<i class="bi bi-record-circle me-1"></i> Start Capture';
                return;
            }
            btnStopPcap.disabled = false;
        } catch (e) {
            alert('Failed to start capture: ' + e);
            btnStartPcap.disabled = false;
            btnStartPcap.innerHTML = '<i class="bi bi-record-circle me-1"></i> Start Capture';
        }
    });

    btnStopPcap?.addEventListener('click', async () => {
        btnStopPcap.disabled = true;
        btnStopPcap.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Analyzing...';

        try {
            const res = await fetch('/api/captures/stop', { method: 'POST' });
            const data = await res.json();
            btnStopPcap.disabled = true;
            btnStopPcap.innerHTML = '<i class="bi bi-stop-circle me-1"></i> Stop Capture';
            btnStartPcap.disabled = false;
            btnStartPcap.innerHTML = '<i class="bi bi-record-circle me-1"></i> Start Capture';

            // Show results
            const resultsBox = document.getElementById('pcap-results-box');
            const summaryBox = document.getElementById('pcap-summary-content');
            if (resultsBox && summaryBox) {
                resultsBox.classList.remove('d-none');
                summaryBox.innerHTML = `
                    <div class="col-md-3"><strong>Packets:</strong> ${data.packet_count || 0}</div>
                    <div class="col-md-3"><strong>TCP Retransmissions:</strong> <span class="text-warning">${data.tcp_retransmissions || 0}</span></div>
                    <div class="col-md-3"><strong>Duplicate ACKs:</strong> ${data.dup_acks || 0}</div>
                    <div class="col-md-3"><strong>TCP Resets:</strong> ${data.tcp_resets || 0}</div>
                    <div class="col-12 mt-2 text-muted fs-9">${data.analysis_notes || ''}</div>
                `;
            }
        } catch (e) {
            alert('Failed to stop capture: ' + e);
            btnStopPcap.disabled = false;
        }
    });

    // Start background telemetry polling immediately
    startPolling();
});

function startPolling() {
    if (pollIntervalId) clearInterval(pollIntervalId);
    pollIntervalId = setInterval(fetchLiveSnapshot, 1500);
    fetchLiveSnapshot(); // Immediate first poll
}

async function fetchLiveSnapshot() {
    try {
        const res = await fetch('/api/dashboard/live');
        if (!res.ok) return;
        const data = await res.json();

        updateDashboardDOM(data);

        // Update charts
        if (window.updateChartsWithData && data.recent_measurements) {
            window.updateChartsWithData(data.recent_measurements, data.interface_stats);
        }
    } catch (e) {
        console.debug('Polling error:', e);
    }
}

function updateDashboardDOM(data) {
    const isRunning = data.is_running || false;
    const btnStart = document.getElementById('btn-start-monitor');
    const btnStop = document.getElementById('btn-stop-monitor');

    if (btnStart && btnStop) {
        if (isRunning) {
            btnStart.disabled = true;
            btnStop.disabled = false;
        } else if (!isCurrentlyMonitoring) {
            btnStart.disabled = false;
            btnStop.disabled = true;
        }
    }

    // Top Navigation pill
    const globalPill = document.getElementById('global-status-pill');
    if (globalPill) {
        if (isRunning) {
            globalPill.className = 'badge rounded-pill bg-success px-3 py-2 text-uppercase fs-7 pulse-animation';
            globalPill.innerHTML = '<i class="bi bi-activity me-1"></i> Monitoring Active';
        } else {
            globalPill.className = 'badge rounded-pill bg-secondary px-3 py-2 text-uppercase fs-7';
            globalPill.innerHTML = '<i class="bi bi-circle-fill me-1 small"></i> System Idle';
        }
    }

    // KPIs
    const pStats = data.primary_stats || {};
    const ifStats = data.interface_stats || {};

    // 1. Status Indicator & Duration
    const ind = document.getElementById('kpi-status-indicator');
    const statusText = document.getElementById('kpi-status-text');
    const durationText = document.getElementById('kpi-duration-text');
    const overallStatus = data.overall_status || 'idle';

    if (ind && statusText) {
        ind.className = `status-dot status-${overallStatus} me-2`;
        statusText.textContent = overallStatus.toUpperCase();
        if (overallStatus === 'normal') statusText.className = 'h5 fw-bold mb-0 text-success';
        else if (overallStatus === 'warning') statusText.className = 'h5 fw-bold mb-0 text-warning';
        else if (overallStatus === 'critical') statusText.className = 'h5 fw-bold mb-0 text-danger';
        else statusText.className = 'h5 fw-bold mb-0 text-secondary';
    }
    if (durationText) durationText.textContent = `Duration: ${data.duration_str || '00:00:00'}`;

    // 2. Latency Metrics
    const avgRtt = document.getElementById('kpi-avg-rtt');
    const minRtt = document.getElementById('kpi-min-rtt');
    const maxRtt = document.getElementById('kpi-max-rtt');
    if (avgRtt) avgRtt.textContent = (pStats.avg_rtt !== undefined && pStats.avg_rtt !== null) ? pStats.avg_rtt : '0.00';
    if (minRtt) minRtt.textContent = (pStats.min_rtt !== undefined && pStats.min_rtt !== null) ? pStats.min_rtt : '0.0';
    if (maxRtt) maxRtt.textContent = (pStats.max_rtt !== undefined && pStats.max_rtt !== null) ? pStats.max_rtt : '0.0';

    // 3. Packet Loss
    const lossText = document.getElementById('kpi-loss-text');
    const lostPkts = document.getElementById('kpi-lost-packets');
    const sentPkts = document.getElementById('kpi-sent-packets');
    const lossVal = pStats.loss_pct !== undefined ? pStats.loss_pct : 0.0;
    if (lossText) {
        lossText.textContent = `${lossVal.toFixed(2)}%`;
        if (lossVal >= 5.0) lossText.className = 'h4 fw-bold mb-0 text-danger';
        else if (lossVal > 0.0) lossText.className = 'h4 fw-bold mb-0 text-warning';
        else lossText.className = 'h4 fw-bold mb-0 text-success';
    }
    if (lostPkts) lostPkts.textContent = pStats.packets_lost || 0;
    if (sentPkts) sentPkts.textContent = pStats.packets_sent || 0;

    // 4. Interface Errors & Drops
    const rxErrors = document.getElementById('kpi-rx-errors');
    const rxErrVal = document.getElementById('kpi-rx-err-val');
    const txErrVal = document.getElementById('kpi-tx-err-val');
    if (rxErrors) rxErrors.textContent = ifStats.total_errors_delta || (ifStats.rx_errors_delta || 0);
    if (rxErrVal) rxErrVal.textContent = ifStats.rx_errors || 0;
    if (txErrVal) txErrVal.textContent = ifStats.tx_errors || 0;

    // 5. Hardware CRC/FCS Counters
    const crcErrors = document.getElementById('kpi-crc-errors');
    const crcDelta = document.getElementById('kpi-crc-delta');
    if (crcErrors) crcErrors.textContent = ifStats.crc_fcs_errors || 0;
    if (crcDelta) crcDelta.textContent = ifStats.crc_fcs_delta || 0;

    // 6. Drops & Speed
    const drops = document.getElementById('kpi-dropped-packets');
    const speed = document.getElementById('kpi-speed-mbps');
    if (drops) drops.textContent = (ifStats.rx_drops || 0) + (ifStats.tx_drops || 0);
    if (speed) speed.textContent = ifStats.link_speed_mbps || '--';

    // 7. Multi-target Telemetry Table Update
    if (data.all_targets && data.all_targets.length > 0) {
        const tbody = document.getElementById('multi-target-tbody');
        if (tbody) {
            tbody.innerHTML = '';
            data.all_targets.forEach(tgt => {
                const tr = document.createElement('tr');
                const badgeClass = tgt.status === 'normal' ? 'bg-success' : (tgt.status === 'warning' ? 'bg-warning text-dark' : (tgt.status === 'critical' ? 'bg-danger' : 'bg-secondary'));
                tr.innerHTML = `
                    <td><span class="badge bg-dark border border-secondary text-info">${(tgt.role || 'target').toUpperCase()}</span></td>
                    <td><code>${tgt.target}</code></td>
                    <td>${tgt.packets_sent} / ${tgt.packets_received}</td>
                    <td><span class="fw-bold ${tgt.loss_pct > 0 ? 'text-danger' : 'text-success'}">${tgt.loss_pct.toFixed(1)}%</span></td>
                    <td>${tgt.current_rtt !== null ? tgt.current_rtt + ' ms' : '<span class="text-danger">TIMEOUT</span>'}</td>
                    <td>${tgt.avg_rtt} ms</td>
                    <td>${tgt.min_rtt || 0.0} / ${tgt.max_rtt || 0.0} ms</td>
                    <td><span class="badge ${badgeClass}">${(tgt.status || 'idle').toUpperCase()}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }
    }
}
