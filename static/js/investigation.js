/**
 * Electrical Interference (EMI) Investigation Controller
 * Handles incident logging, comparative test execution (Tests A-D),
 * and triggers the backend scientific correlation engine.
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnPrefill = document.getElementById('btn-prefill-example');
    const btnSaveIncident = document.getElementById('btn-save-incident');
    const btnRunCorrelation = document.getElementById('btn-run-correlation');

    // Pre-fill Example button
    btnPrefill?.addEventListener('click', () => {
        document.getElementById('inc-title').value = 'Automated Stamping Press / VFD Motor Inductive Coupling';
        document.getElementById('inc-location').value = 'Assembly Plant B, Tray Line 04';
        document.getElementById('inc-cable-type').value = 'Cat5e UTP (Unshielded)';
        document.getElementById('inc-cable-length').value = '32.0';
        document.getElementById('inc-distance').value = '0.10';
        document.getElementById('inc-source-type').value = 'vfd';
        document.getElementById('inc-operating').checked = true;
        document.getElementById('inc-crc').value = '18';
        document.getElementById('inc-notes').value = (
            'Cat5e cable run bundled alongside 480V 3-phase motor power lines inside shared metallic conduit. '
            'Severe packet loss spikes coincide with press cycle ramp-up.'
        );

        // Pre-fill Tests A-D
        document.getElementById('test-a-rtt').value = '1.15';
        document.getElementById('test-a-loss').value = '0.0';
        document.getElementById('test-a-crc').value = '0';

        document.getElementById('test-b-rtt').value = '42.8';
        document.getElementById('test-b-loss').value = '9.5';
        document.getElementById('test-b-crc').value = '18';

        document.getElementById('test-c-rtt').value = '1.25';
        document.getElementById('test-c-loss').value = '0.0';
        document.getElementById('test-c-crc').value = '0';

        document.getElementById('test-d-rtt').value = '1.08';
        document.getElementById('test-d-loss').value = '0.0';
        document.getElementById('test-d-crc').value = '0';
    });

    // Save Incident Handler
    btnSaveIncident?.addEventListener('click', async () => {
        const title = document.getElementById('inc-title').value.trim();
        if (!title) {
            alert('Please provide an incident title.');
            return;
        }

        const payload = {
            title: title,
            location: document.getElementById('inc-location').value.trim(),
            session_id: document.getElementById('inc-session-id').value || null,
            cable_type: document.getElementById('inc-cable-type').value,
            cable_length_m: parseFloat(document.getElementById('inc-cable-length').value) || 25.0,
            distance_to_source_m: parseFloat(document.getElementById('inc-distance').value) || 0.5,
            electrical_source_type: document.getElementById('inc-source-type').value,
            equipment_operating: document.getElementById('inc-operating').checked,
            crc_fcs_observed: parseInt(document.getElementById('inc-crc').value) || 0,
            investigator_notes: document.getElementById('inc-notes').value.trim()
        };

        btnSaveIncident.disabled = true;
        btnSaveIncident.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Saving...';

        try {
            const res = await fetch('/api/incidents', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.success) {
                // Save comparative tests for this incident
                const incId = data.incident_id;
                await saveComparativeTestsForIncident(incId);
                alert(`Incident recorded successfully! Reference ID: #${incId}`);
            } else {
                alert('Failed to save incident: ' + (data.error || 'Server error'));
            }
        } catch (e) {
            alert('Error saving incident: ' + e);
        } finally {
            btnSaveIncident.disabled = false;
            btnSaveIncident.innerHTML = '<i class="bi bi-save me-1"></i> Save Incident Record';
        }
    });

    // Run Correlation Engine Handler
    btnRunCorrelation?.addEventListener('click', async () => {
        btnRunCorrelation.disabled = true;
        btnRunCorrelation.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Correlating...';

        const tests = [
            {
                test_code: 'A',
                title: 'Normal Baseline (Equipment Off)',
                avg_rtt: parseFloat(document.getElementById('test-a-rtt').value) || 1.2,
                packet_loss_pct: parseFloat(document.getElementById('test-a-loss').value) || 0.0,
                crc_error_delta: parseInt(document.getElementById('test-a-crc').value) || 0,
                duration_sec: 60
            },
            {
                test_code: 'B',
                title: 'Suspected EMI Active',
                avg_rtt: parseFloat(document.getElementById('test-b-rtt').value) || 35.0,
                packet_loss_pct: parseFloat(document.getElementById('test-b-loss').value) || 5.0,
                crc_error_delta: parseInt(document.getElementById('test-b-crc').value) || 0,
                duration_sec: 60
            },
            {
                test_code: 'C',
                title: 'Cable Rerouted Away',
                avg_rtt: parseFloat(document.getElementById('test-c-rtt').value) || 1.3,
                packet_loss_pct: parseFloat(document.getElementById('test-c-loss').value) || 0.0,
                crc_error_delta: parseInt(document.getElementById('test-c-crc').value) || 0,
                duration_sec: 60
            },
            {
                test_code: 'D',
                title: 'Shielded Cable Test',
                avg_rtt: parseFloat(document.getElementById('test-d-rtt').value) || 1.1,
                packet_loss_pct: parseFloat(document.getElementById('test-d-loss').value) || 0.0,
                crc_error_delta: parseInt(document.getElementById('test-d-crc').value) || 0,
                duration_sec: 60
            }
        ];

        const sessionId = document.getElementById('inc-session-id')?.value || null;

        try {
            const res = await fetch('/api/analysis/correlate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: sessionId ? parseInt(sessionId) : null,
                    comparative_tests: tests
                })
            });
            const data = await res.json();
            if (data.success && data.diagnosis) {
                renderCorrelationDiagnosis(data.diagnosis);
            } else {
                alert('Analysis failed: ' + (data.error || 'Server error'));
            }
        } catch (e) {
            alert('Correlation error: ' + e);
        } finally {
            btnRunCorrelation.disabled = false;
            btnRunCorrelation.innerHTML = '<i class="bi bi-cpu me-1"></i> Run Scientific Correlation Engine';
        }
    });
});

async function saveComparativeTestsForIncident(incidentId) {
    const tests = [
        {
            test_code: 'A',
            title: 'Normal Baseline (Equipment Off)',
            description: 'Electrical machinery powered OFF',
            avg_rtt: parseFloat(document.getElementById('test-a-rtt').value) || 1.2,
            packet_loss_pct: parseFloat(document.getElementById('test-a-loss').value) || 0.0,
            crc_error_delta: parseInt(document.getElementById('test-a-crc').value) || 0,
            duration_sec: 60
        },
        {
            test_code: 'B',
            title: 'Suspected EMI Active',
            description: 'Machinery operational in normal cycle',
            avg_rtt: parseFloat(document.getElementById('test-b-rtt').value) || 35.0,
            packet_loss_pct: parseFloat(document.getElementById('test-b-loss').value) || 5.0,
            crc_error_delta: parseInt(document.getElementById('test-b-crc').value) || 0,
            duration_sec: 60
        },
        {
            test_code: 'C',
            title: 'Cable Rerouted',
            description: 'Separated from suspected equipment',
            avg_rtt: parseFloat(document.getElementById('test-c-rtt').value) || 1.3,
            packet_loss_pct: parseFloat(document.getElementById('test-c-loss').value) || 0.0,
            crc_error_delta: parseInt(document.getElementById('test-c-crc').value) || 0,
            duration_sec: 60
        },
        {
            test_code: 'D',
            title: 'Shielded Cable Swap',
            description: 'Cat6a STP cable installed and grounded',
            avg_rtt: parseFloat(document.getElementById('test-d-rtt').value) || 1.1,
            packet_loss_pct: parseFloat(document.getElementById('test-d-loss').value) || 0.0,
            crc_error_delta: parseInt(document.getElementById('test-d-crc').value) || 0,
            duration_sec: 60
        }
    ];

    for (const t of tests) {
        await fetch(`/api/incidents/${incidentId}/tests`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(t)
        });
    }
}

function renderCorrelationDiagnosis(diag) {
    document.getElementById('correlation-placeholder').classList.add('d-none');
    const out = document.getElementById('correlation-output');
    out.classList.remove('d-none');

    // Category title
    const titleEl = document.getElementById('diag-category-title');
    titleEl.textContent = diag.summary_title || diag.category_label;

    // Confidence badge & progress bar
    const conf = diag.confidence_score || 0.0;
    const badge = document.getElementById('confidence-meter-badge');
    const bar = document.getElementById('diag-confidence-bar');
    badge.textContent = `Confidence: ${conf.toFixed(1)}%`;
    bar.style.width = `${conf}%`;
    if (conf >= 70) {
        bar.className = 'progress-bar bg-success';
        badge.className = 'badge bg-success';
    } else if (conf >= 40) {
        bar.className = 'progress-bar bg-warning text-dark';
        badge.className = 'badge bg-warning text-dark';
    } else {
        bar.className = 'progress-bar bg-danger';
        badge.className = 'badge bg-danger';
    }

    // Findings
    const findingsList = document.getElementById('diag-findings-list');
    findingsList.innerHTML = '';
    (diag.findings || []).forEach(f => {
        const li = document.createElement('li');
        li.className = 'mb-1';
        li.textContent = f;
        findingsList.appendChild(li);
    });

    // Recommendations
    const recsList = document.getElementById('diag-recommendations-list');
    recsList.innerHTML = '';
    (diag.recommendations || []).forEach(r => {
        const li = document.createElement('li');
        li.className = 'mb-1';
        li.textContent = r;
        recsList.appendChild(li);
    });

    // Disclaimer
    const disclBox = document.getElementById('diag-disclaimer-box');
    const disclText = document.getElementById('diag-disclaimer-text');
    if (diag.disclaimers && diag.disclaimers.length > 0) {
        disclBox.classList.remove('d-none');
        disclText.textContent = diag.disclaimers[0];
    } else {
        disclBox.classList.add('d-none');
    }
}
