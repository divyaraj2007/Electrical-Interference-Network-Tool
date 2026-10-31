/**
 * Device Management Interactive Controller
 * Real-time device registration, telemetry inspection, and connection management.
 */

document.addEventListener("DOMContentLoaded", () => {
    initDeviceRegistrationModal();
    initActionButtons();
    initRealTimeDeviceStream();
});

/**
 * Handle Device Registration Modal and token generation
 */
function initDeviceRegistrationModal() {
    const btnGenToken = document.getElementById("btn-gen-modal-token");
    const tokenInput = document.getElementById("reg-token");
    const regForm = document.getElementById("form-register-device");

    if (btnGenToken && tokenInput) {
        btnGenToken.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/devices/token/generate");
                const data = await res.json();
                if (data.token) {
                    tokenInput.value = data.token;
                }
            } catch (err) {
                console.error("Token generation error:", err);
            }
        });
    }

    if (regForm) {
        regForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const payload = {
                device_type: document.getElementById("reg-device-type").value,
                device_id: document.getElementById("reg-device-id").value.trim(),
                hostname: document.getElementById("reg-hostname").value.trim(),
                ip_address: document.getElementById("reg-ip").value.trim(),
                os_info: document.getElementById("reg-os").value,
                auth_token: document.getElementById("reg-token").value.trim()
            };

            try {
                const res = await fetch("/api/devices/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    alert(`Device ${payload.device_id} registered successfully!`);
                    window.location.reload();
                } else {
                    alert("Registration failed: " + (data.error || "Unknown error"));
                }
            } catch (err) {
                alert("Network error while registering device: " + err.message);
            }
        });
    }

    // Refresh devices button
    document.getElementById("btn-refresh-devices")?.addEventListener("click", () => {
        window.location.reload();
    });
}

/**
 * Attach listeners to Reconnect and Delete buttons
 */
function initActionButtons() {
    document.addEventListener("click", async (e) => {
        const btnReconnect = e.target.closest(".btn-reconnect-dev");
        if (btnReconnect) {
            const devId = btnReconnect.dataset.deviceId;
            try {
                const res = await fetch(`/api/devices/${encodeURIComponent(devId)}/reconnect`, { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    btnReconnect.classList.remove("btn-outline-info");
                    btnReconnect.classList.add("btn-success");
                    setTimeout(() => btnReconnect.classList.replace("btn-success", "btn-outline-info"), 1500);
                } else {
                    alert("Reconnect failed: " + data.error);
                }
            } catch (err) {
                console.error("Reconnect error:", err);
            }
        }

        const btnDelete = e.target.closest(".btn-delete-dev");
        if (btnDelete) {
            const devId = btnDelete.dataset.deviceId;
            if (confirm(`Are you sure you want to remove device '${devId}'?`)) {
                try {
                    const res = await fetch(`/api/devices/${encodeURIComponent(devId)}`, { method: "DELETE" });
                    const data = await res.json();
                    if (data.success) {
                        window.location.reload();
                    } else {
                        alert("Deletion failed.");
                    }
                } catch (err) {
                    alert("Delete error: " + err.message);
                }
            }
        }
    });
}

/**
 * Connect to Server-Sent Events stream for real-time device updates
 */
function initRealTimeDeviceStream() {
    if (window.location.search.includes("static_capture=1")) {
        return; // Skip persistent SSE stream for headless screenshot capture
    }
    if (typeof EventSource !== "undefined") {
        const sse = new EventSource("/api/devices/stream");

        sse.onmessage = (event) => {
            try {
                const payload = JSON.parse(event.data);
                updateDeviceUI(payload.devices || []);
            } catch (e) {
                console.error("SSE parse error:", e);
            }
        };

        sse.onerror = () => {
            // If SSE disconnects, fallback to occasional polling
            setTimeout(() => {
                fetchDevicesFallback();
            }, 5000);
        };
    } else {
        setInterval(fetchDevicesFallback, 4000);
    }
}

/**
 * Update UI Cards and Table with live telemetry from SSE
 */
function updateDeviceUI(devices) {
    devices.forEach((dev) => {
        // Update Card elements
        const cardCol = document.querySelector(`.device-card-col[data-device-id="${dev.device_id}"]`);
        if (cardCol) {
            const statusBadge = cardCol.querySelector(".dev-status-badge");
            if (statusBadge) {
                statusBadge.className = `badge rounded-pill fs-8 dev-status-badge ${
                    dev.status === "online" ? "bg-success" : (dev.status === "testing" ? "bg-warning text-dark" : "bg-secondary")
                }`;
                statusBadge.innerHTML = `<i class="bi bi-circle-fill me-1 small"></i> ${dev.status.toUpperCase()}`;
            }

            const cpuEl = cardCol.querySelector(".dev-cpu-val");
            if (cpuEl) cpuEl.textContent = `${(dev.cpu_pct || 0).toFixed(1)}%`;

            const memEl = cardCol.querySelector(".dev-mem-val");
            if (memEl) memEl.textContent = `${(dev.mem_pct || 0).toFixed(1)}%`;

            const hbEl = cardCol.querySelector(".dev-last-hb");
            if (hbEl) hbEl.textContent = dev.last_heartbeat || "Never";
        }

        // Update Table row
        const tableRow = document.querySelector(`tr[data-row-device-id="${dev.device_id}"]`);
        if (tableRow) {
            const rowStatus = tableRow.querySelector(".dev-row-status");
            if (rowStatus) {
                rowStatus.className = `badge fs-9 dev-row-status ${
                    dev.status === "online" ? "bg-success" : (dev.status === "testing" ? "bg-warning text-dark" : "bg-secondary")
                }`;
                rowStatus.textContent = dev.status.toUpperCase();
            }

            const rowHb = tableRow.querySelector(".dev-row-hb");
            if (rowHb) rowHb.textContent = dev.last_heartbeat || "Never";
        }
    });
}

async function fetchDevicesFallback() {
    try {
        const res = await fetch("/api/devices");
        const data = await res.json();
        if (data.devices) {
            updateDeviceUI(data.devices);
        }
    } catch (err) {
        console.debug("Fallback fetch error:", err);
    }
}
