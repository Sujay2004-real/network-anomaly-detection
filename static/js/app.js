// Global State
let isRunning = false;
let mainChart = null;
let pollInterval = null;
const POLL_RATE_MS = 1500;

const els = {
    statusBox: document.getElementById('sidebar-status-box'),
    statusPulse: document.getElementById('status-pulse'),
    statusText: document.getElementById('sidebar-status-text'),
    runModeSelect: document.getElementById('run-mode-select'),
    ifaceGroup: document.getElementById('iface-group'),
    ifaceSelect: document.getElementById('iface-select'),
    btnStart: document.getElementById('btn-start'),
    btnStop: document.getElementById('btn-stop'),
    pipelineControls: document.getElementById('pipeline-controls'),
    trafficModeRadios: document.getElementsByName('traffic-mode'),
    
    valThreatLevel: document.getElementById('val-threat-level'),
    valDataRate: document.getElementById('val-data-rate'),
    valPacketRate: document.getElementById('val-packet-rate'),
    valAnomalyRatio: document.getElementById('val-anomaly-ratio'),
    
    cardThreat: document.getElementById('card-threat'),
    cardAnomaly: document.getElementById('card-anomaly'),
    
    logContainer: document.getElementById('log-container')
};

// Initialize Chart.js
function initChart() {
    const ctx = document.getElementById('mainChart').getContext('2d');
    
    Chart.defaults.color = '#8b949e';
    Chart.defaults.font.family = "'Inter', sans-serif";
    
    mainChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [], // Timestamps
            datasets: [
                {
                    label: 'Packet Rate (pkts/sec)',
                    data: [],
                    borderColor: '#58a6ff',
                    backgroundColor: 'rgba(88, 166, 255, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                    yAxisID: 'y'
                },
                {
                    label: 'Threat Score (%)',
                    data: [],
                    type: 'bar',
                    backgroundColor: 'rgba(207, 34, 46, 0.7)',
                    borderColor: '#cf222e',
                    borderWidth: 1,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { position: 'top', labels: { usePointStyle: true } },
                tooltip: { backgroundColor: 'rgba(22, 27, 34, 0.9)', titleColor: '#fff', bodyColor: '#c9d1d9', borderColor: '#30363d', borderWidth: 1 }
            },
            scales: {
                x: { grid: { color: '#30363d' } },
                y: {
                    type: 'linear', display: true, position: 'left',
                    title: { display: true, text: 'Packet Rate', color: '#58a6ff' },
                    grid: { color: '#30363d' }
                },
                y1: {
                    type: 'linear', display: true, position: 'right',
                    title: { display: true, text: 'Threat Score (%)', color: '#cf222e' },
                    grid: { drawOnChartArea: false },
                    min: 0,
                    max: 100
                }
            },
            animation: { duration: 0 } // Disable animation for live data to prevent lag
        }
    });
}

// Format numbers
function formatBytes(bytes) {
    if (bytes === 0) return '0 B/s';
    const k = 1024;
    const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num) {
    return new Intl.NumberFormat('en-US').format(num);
}

// Update UI state based on running status
function updateRunningState(running) {
    if (running !== isRunning) {
        isRunning = running;
        if (isRunning) {
            els.statusBox.classList.add('active');
            els.statusPulse.className = 'pulse online';
            els.statusText.textContent = 'Pipeline Active';
            
            els.btnStart.style.display = 'none';
            els.btnStop.style.display = 'flex';
            els.runModeSelect.disabled = true;
            els.ifaceSelect.disabled = true;
            els.pipelineControls.style.display = 'block';
        } else {
            els.statusBox.classList.remove('active');
            els.statusPulse.className = 'pulse offline';
            els.statusText.textContent = 'Pipeline Offline';
            
            els.btnStart.style.display = 'flex';
            els.btnStop.style.display = 'none';
            els.runModeSelect.disabled = false;
            els.ifaceSelect.disabled = false;
            els.pipelineControls.style.display = 'none';
        }
    }
}

// Fetch and update data
async function pollStatus() {
    try {
        const res = await fetch(`/api/status?_t=${new Date().getTime()}`, { cache: "no-store" });
        const data = await res.json();
        
        updateRunningState(data.running);
        
        if (data.running || data.status.status !== "Stopped") {
            
            if (data.history && data.history.length > 0) {
                const latest = data.history[data.history.length - 1];
                
                // Update Metrics from the LATEST history point to guarantee synchronization
                els.valDataRate.textContent = formatBytes(latest.byte_rate);
                els.valPacketRate.textContent = formatNumber(latest.packet_rate) + ' pkts/sec';
                
                const anomRate = latest.anomaly_ratio;
                els.valAnomalyRatio.textContent = anomRate + '%';
                if (anomRate > 5) els.valAnomalyRatio.style.color = 'var(--color-danger)';
                else if (anomRate > 0) els.valAnomalyRatio.style.color = 'var(--color-warning)';
                else els.valAnomalyRatio.style.color = 'var(--color-accent)';
                
                // Threat Level
                const threat = latest.threat_score;
                els.cardThreat.className = 'metric-card'; // reset
                if (threat < 15) {
                    els.cardThreat.classList.add('threat-safe');
                    els.valThreatLevel.textContent = `SAFE (${threat}%)`;
                    els.valThreatLevel.style.color = 'var(--color-success)';
                } else if (threat < 50) {
                    els.cardThreat.classList.add('threat-warning');
                    els.valThreatLevel.textContent = `WARNING (${threat}%)`;
                    els.valThreatLevel.style.color = 'var(--color-warning)';
                } else {
                    els.cardThreat.classList.add('threat-critical');
                    els.valThreatLevel.textContent = `CRITICAL ATTACK (${threat}%)`;
                    els.valThreatLevel.style.color = 'var(--color-danger)';
                }

                // Update Chart
                mainChart.data.labels = data.history.map(pt => pt.time);
                mainChart.data.datasets[0].data = data.history.map(pt => pt.packet_rate);
                mainChart.data.datasets[1].data = data.history.map(pt => pt.threat_score);
                mainChart.update();
            }
            
            // Update mode radio button if changed externally
            const currentMode = data.status.mode || "Normal";
            for (let radio of els.trafficModeRadios) {
                if (radio.value === currentMode) {
                    radio.checked = true;
                    break;
                }
            }
            
            // Update Logs
            if (data.alerts && data.alerts.length > 0) {
                renderLogs(data.alerts);
            } else {
                els.logContainer.innerHTML = '<div class="empty-logs">No anomalies detected yet...</div>';
            }
        }
        
    } catch (e) {
        console.error("Error polling status:", e);
    }
}

function renderLogs(alerts) {
    els.logContainer.innerHTML = '';
    // reverse to show newest first
    const reversed = [...alerts].reverse();
    
    reversed.forEach(alert => {
        const div = document.createElement('div');
        // confidence is a string like "52%", parse it
        const confNum = parseInt(alert.confidence) || 0;
        div.className = `log-entry ${confNum < 50 ? 'warning' : 'critical'}`;
        div.innerHTML = `
            <span class="log-time">${alert.timestamp}</span>
            <span class="log-msg">${alert.anomaly_type}</span>
            <span class="log-details" style="font-size: 0.75rem; color: var(--text-muted)">
                ${alert.src_ip} &rarr; ${alert.dst_ip}:${alert.dst_port}
            </span>
        `;
        els.logContainer.appendChild(div);
    });
}

// Event Listeners
els.runModeSelect.addEventListener('change', (e) => {
    if (e.target.value === "Live Sniffing") {
        els.ifaceGroup.style.display = 'block';
    } else {
        els.ifaceGroup.style.display = 'none';
    }
});

els.trafficModeRadios.forEach(radio => {
    radio.addEventListener('change', async (e) => {
        if (e.target.checked && isRunning) {
            await fetch('/api/mode', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mode: e.target.value})
            });
        }
    });
});

els.btnStart.addEventListener('click', async () => {
    els.btnStart.disabled = true;
    els.btnStart.textContent = "Starting...";
    
    await fetch('/api/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            run_mode: els.runModeSelect.value,
            iface: els.ifaceSelect.value
        })
    });
    
    // Give it a moment, then the poller will catch it
    setTimeout(() => {
        els.btnStart.disabled = false;
        els.btnStart.textContent = "🟢 Start Detection Pipeline";
        pollStatus();
    }, 2000);
});

els.btnStop.addEventListener('click', async () => {
    els.btnStop.disabled = true;
    els.btnStop.textContent = "Stopping...";
    
    await fetch('/api/stop', { method: 'POST' });
    
    setTimeout(() => {
        els.btnStop.disabled = false;
        els.btnStop.textContent = "🔴 Stop Detection Pipeline";
        pollStatus();
    }, 1000);
});

// Initial Setup
async function init() {
    initChart();
    
    // Fetch interfaces
    try {
        const res = await fetch('/api/interfaces');
        const data = await res.json();
        if (data.interfaces && data.interfaces.length > 0) {
            data.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface;
                opt.textContent = iface;
                els.ifaceSelect.appendChild(opt);
            });
        }
    } catch(e) {
        console.error("Failed to fetch interfaces", e);
    }
    
    // Start Poller
    pollStatus();
    pollInterval = setInterval(pollStatus, POLL_RATE_MS);
}

document.addEventListener('DOMContentLoaded', init);
