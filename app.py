import os
import sys
import json
import time
import uuid
import subprocess
import psutil
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# File paths
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = os.path.join(PROJECT_DIR, "data", "live_status.json")
HISTORY_FILE = os.path.join(PROJECT_DIR, "data", "history.json")
ALERTS_FILE = os.path.join(PROJECT_DIR, "data", "alerts.json")
PID_FILE = os.path.join(PROJECT_DIR, "data", "pipeline.pid") # Kept for legacy cleanup

# Ensure directories exist
os.makedirs(os.path.join(PROJECT_DIR, "data"), exist_ok=True)

def robust_read_json(file_path, retries=5, delay=0.05, default=None):
    for i in range(retries):
        try:
            if not os.path.exists(file_path):
                return default
            with open(file_path, 'r') as f:
                res = json.load(f)
                return res if res is not None else default
        except (PermissionError, json.JSONDecodeError):
            if i < retries - 1:
                time.sleep(delay)
            else:
                return default
    return default

def robust_write_json(file_path, data, retries=5, delay=0.05):
    temp_path = f"{file_path}.{uuid.uuid4().hex}.tmp"
    for i in range(retries):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(temp_path, 'w') as f:
                json.dump(data, f)
            os.replace(temp_path, file_path)
            return
        except PermissionError:
            if i < retries - 1:
                time.sleep(delay)
            else:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                raise

# ── Helper: kill a pipeline process by scanning with psutil ──
def _kill_existing_pipeline():
    """Terminate any lingering detect.py subprocess from a previous session."""
    killed_any = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline')
            if cmdline:
                # Check if this is a python process running detect.py
                if any('detect.py' in cmd for cmd in cmdline) and 'python' in proc.info.get('name', '').lower():
                    proc.kill()
                    killed_any = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    # Also clean up PID_FILE if it exists from older versions
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except Exception:
            pass
            
    return killed_any

# ── Helper: discover network interfaces for live sniffing ──
def _get_network_interfaces():
    """Return a list of Windows network adapter names via PowerShell."""
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-NetAdapter | Select-Object -ExpandProperty Name'],
            capture_output=True, text=True, timeout=5
        )
        names = [ln.strip() for ln in result.stdout.strip().split('\n') if ln.strip()]
        return names
    except Exception:
        return []

def is_pipeline_running():
    if os.path.exists(STATUS_FILE):
        data = robust_read_json(STATUS_FILE, default={})
        return data.get("status") in ["Running", "Starting"]
    return False

# Initialize state on startup (Kill any old pipelines)
with app.app_context():
    _kill_existing_pipeline()
    _init_status = {
        "status": "Stopped",
        "mode": "Normal",
        "run_mode": "",
        "packet_rate": 0,
        "byte_rate": 0,
        "anomaly_rate": 0,
        "total_packets": 0,
        "total_anomalies": 0,
        "threat_score": 0
    }
    robust_write_json(STATUS_FILE, _init_status)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    running = is_pipeline_running()
    
    status_data = {
        "status": "Stopped",
        "mode": "Normal",
        "packet_rate": 0,
        "byte_rate": 0,
        "anomaly_rate": 0,
        "total_packets": 0,
        "total_anomalies": 0,
        "threat_score": 0
    }
    
    if running:
        status_data = robust_read_json(STATUS_FILE, default=status_data)
        # Verify it hasn't somehow become stale
        if status_data.get("status") not in ["Running", "Starting"]:
            running = False
            
    history_data = robust_read_json(HISTORY_FILE, default=[])
    alerts_data = robust_read_json(ALERTS_FILE, default=[])
    
    return jsonify({
        "running": running,
        "status": status_data,
        "history": history_data,
        "alerts": alerts_data
    })

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify({"interfaces": _get_network_interfaces()})

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.json or {}
    run_mode = data.get("run_mode", "Live Sniffing")
    iface = data.get("iface")
    
    # Kill any leftover process first
    _kill_existing_pipeline()
    
    # Wipe old logs to prevent previous alerts from showing as new threats
    robust_write_json(HISTORY_FILE, [])
    robust_write_json(ALERTS_FILE, [])
    
    # Write "Starting" status immediately so UI doesn't think it failed
    robust_write_json(STATUS_FILE, {
        "status": "Starting",
        "mode": "Normal",
        "run_mode": run_mode,
        "packet_rate": 0,
        "byte_rate": 0,
        "anomaly_rate": 0,
        "total_packets": 0,
        "total_anomalies": 0,
        "threat_score": 0
    })
    
    # Launch detect.py in background
    mode_arg = "live" if run_mode == "Live Sniffing" else "playback"
    
    # Safely determine the python executable (in case app.py was run via flask wrapper)
    python_exe = sys.executable if "python" in sys.executable.lower() else "python"
    
    cmd = [python_exe, os.path.join(PROJECT_DIR, "detect.py"), "--mode", mode_arg]
    if iface and iface != "Auto (default)":
        cmd.extend(["--iface", iface])
        
    log_file = open(os.path.join(PROJECT_DIR, "detect_log.txt"), "a")
    subprocess.Popen(
        cmd, 
        cwd=PROJECT_DIR,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    
    return jsonify({"success": True})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    _kill_existing_pipeline()
    robust_write_json(STATUS_FILE, {
        "status": "Stopped",
        "mode": "Normal",
        "run_mode": "",
        "packet_rate": 0,
        "byte_rate": 0,
        "anomaly_rate": 0,
        "total_packets": 0,
        "total_anomalies": 0,
        "threat_score": 0
    })
    return jsonify({"success": True})

@app.route('/api/mode', methods=['POST'])
def api_mode():
    data = request.json or {}
    new_mode = data.get("mode")
    if new_mode in ["Normal", "PortScan", "DDoS"]:
        status_data = robust_read_json(STATUS_FILE, default={})
        status_data["mode"] = new_mode
        robust_write_json(STATUS_FILE, status_data)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid mode"}), 400

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=8501)
