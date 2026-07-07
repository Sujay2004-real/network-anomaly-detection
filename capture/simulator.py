import os
import time
import json
import uuid
import random
import numpy as np
import pandas as pd
from datetime import datetime
from models.detector import AnomalyDetector, FEATURE_COLS

STATUS_FILE = r"C:\Users\sujay\.gemini\antigravity\scratch\network-anomaly-detection\data\live_status.json"
HISTORY_FILE = r"C:\Users\sujay\.gemini\antigravity\scratch\network-anomaly-detection\data\history.json"
ALERTS_FILE = r"C:\Users\sujay\.gemini\antigravity\scratch\network-anomaly-detection\data\alerts.json"

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

class TrafficSimulator:
    def __init__(self, dataset_dir, model_dir, mode="playback", iface=None):
        self.dataset_dir = dataset_dir
        self.model_dir = model_dir
        self.mode = mode
        self.iface = iface  # Network interface for live sniffing (None = default)
        self.sniffing_error = None
        self.detector = AnomalyDetector()
        
        # Try loading the model
        try:
            self.detector.load(model_dir)
            self.model_loaded = True
            print("Simulator loaded trained model successfully.")
        except Exception as e:
            self.model_loaded = False
            print(f"Simulator warning: Could not load trained model ({e}). Alerts will use threshold-based fallback.")
            
        self.active_mode = "Normal" # Maintained for compatibility with dashboard if needed
        self.is_running = False
        
        # Load dataset files or prepare cache
        self.cache = {}
        self.load_dataset_files()
        
        # Initialize files
        self.reset_files()

    def load_dataset_files(self):
        """Loads sections of the Kaggle CSV files into memory to play back quickly."""
        files_to_load = {
            'benign': ('Monday-WorkingHours.pcap_ISCX.csv', None),
            'portscan': ('Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', 'PortScan'),
            'ddos': ('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', 'DDoS')
        }
        
        for key, (f_name, target_label) in files_to_load.items():
            f_path = os.path.join(r"C:\Users\sujay\.cache\kagglehub\datasets\chethuhn\network-intrusion-dataset\versions\1", f_name)
            if os.path.exists(f_path):
                try:
                    print(f"Loading playback samples from {f_name}...")
                    temp_df = pd.read_csv(f_path, nrows=0)
                    actual_cols = list(temp_df.columns)
                    cols_to_read = []
                    for col_name in FEATURE_COLS + ['Label']:
                        matched = next((c for c in actual_cols if c.strip() == col_name), None)
                        if matched:
                            cols_to_read.append(matched)
                    
                    df = pd.read_csv(f_path, nrows=100000, usecols=cols_to_read)
                    df.columns = [c.strip() for c in df.columns]
                    
                    if target_label:
                        attack_df = df[df['Label'] == target_label].copy()
                        benign_df = df[df['Label'] == 'BENIGN'].copy()
                        self.cache[f"{key}_attack"] = attack_df
                        self.cache[f"{key}_noise"] = benign_df
                        print(f"Loaded {len(attack_df)} attacks and {len(benign_df)} noise rows for {key}.")
                    else:
                        self.cache[key] = df
                        print(f"Loaded {len(df)} benign baseline rows.")
                except Exception as e:
                    print(f"Failed to load {f_name}: {e}. Will use synthetic generation.")
            else:
                print(f"File {f_name} not found. Will use synthetic generation.")

    def reset_files(self):
        """Resets the JSON logs to a clean state."""
        robust_write_json(HISTORY_FILE, [])
        robust_write_json(ALERTS_FILE, [])

    def generate_synthetic_flow(self, mode):
        """Generates realistic synthetic flow features as a fallback."""
        dst_port = 80
        flow_duration = random.randint(100, 5000)
        fwd_packets = random.randint(1, 10)
        bwd_packets = random.randint(1, 10)
        fwd_len = fwd_packets * random.randint(64, 1000)
        bwd_len = bwd_packets * random.randint(64, 1000)
        syn_count = 0
        rst_count = 0
        psh_count = 0
        ack_count = total_pkts = fwd_packets + bwd_packets
        
        if mode == "Normal":
            dst_port = random.choice([80, 443, 22, 53])
        elif mode == "PortScan":
            dst_port = random.randint(1, 1024)
            syn_count = 1
            fwd_packets = 1
            bwd_packets = 0
            fwd_len = 64
            bwd_len = 0
            flow_duration = 0
        elif mode == "DDoS":
            dst_port = 80
            fwd_packets = random.randint(100, 500)
            bwd_packets = 0
            fwd_len = fwd_packets * 64
            bwd_len = 0
            flow_duration = random.randint(10, 100)
            syn_count = fwd_packets
            
        total_len = fwd_len + bwd_len
        total_pkts = fwd_packets + bwd_packets
        duration_sec = flow_duration / 1000000.0 if flow_duration > 0 else 0.001
        
        return {
            'Destination Port': dst_port,
            'Flow Duration': flow_duration,
            'Total Fwd Packets': fwd_packets,
            'Total Backward Packets': bwd_packets,
            'Total Length of Fwd Packets': fwd_len,
            'Total Length of Bwd Packets': bwd_len,
            'Flow Bytes/s': total_len / duration_sec,
            'Flow Packets/s': total_pkts / duration_sec,
            'Average Packet Size': total_len / total_pkts if total_pkts > 0 else 0,
            'SYN Flag Count': syn_count,
            'RST Flag Count': rst_count,
            'PSH Flag Count': psh_count,
            'ACK Flag Count': ack_count,
            'src_ip': f"192.168.1.{random.randint(2, 254)}" if mode != "PortScan" and mode != "DDoS" else "10.0.0.15",
            'dst_ip': "192.168.1.100",
            'Protocol': 6 if syn_count > 0 or ack_count > 0 else 17
        }

    def get_flow_sample(self):
        """Fetches a batch of flow records depending on the active simulation mode."""
        mode = self.active_mode
        batch_size = random.randint(15, 30)
        
        flows = []
        labels = []
        
        if mode == "Normal" and 'benign' in self.cache:
            df_sample = self.cache['benign'].sample(n=batch_size, replace=True)
            flows = df_sample.to_dict('records')
            labels = ['BENIGN'] * len(flows)
        elif mode == "PortScan" and 'portscan_attack' in self.cache:
            df_attack = self.cache['portscan_attack'].sample(n=batch_size, replace=True)
            flows = df_attack.to_dict('records')
            labels = [f"PortScan_Attack" for _ in range(batch_size)]
        elif mode == "DDoS" and 'ddos_attack' in self.cache:
            df_attack = self.cache['ddos_attack'].sample(n=batch_size, replace=True)
            flows = df_attack.to_dict('records')
            labels = [f"DDoS_Attack" for _ in range(batch_size)]
        else:
            for _ in range(batch_size):
                flows.append(self.generate_synthetic_flow(mode))
                labels.append(mode)
                
        for f in flows:
            if 'src_ip' not in f or pd.isna(f['src_ip']):
                f['src_ip'] = f"192.168.1.{random.randint(2, 254)}" if mode == "Normal" else "10.0.2.15"
            if 'dst_ip' not in f or pd.isna(f['dst_ip']):
                f['dst_ip'] = "192.168.1.100"
            if 'Protocol' not in f or pd.isna(f['Protocol']):
                f['Protocol'] = 6
                
        return pd.DataFrame(flows), labels

    def get_live_flow_sample(self):
        """Sniffs live packets from the network and extracts flow features.
        
        Returns:
            df_flows: DataFrame of flow-level features
            labels: list of default labels
            raw_packet_count: number of raw packets captured (before flow aggregation)
        """
        from scapy.all import sniff
        from features.extractor import extract_flow_features
        
        # Sniff packets for 1.5 seconds
        try:
            # We filter for IP packets to keep it focused.
            # If a specific interface was chosen (e.g. VMware adapter),
            # sniff only on that adapter; otherwise use scapy's default.
            sniff_kwargs = {"filter": "ip", "timeout": 1.5}
            if self.iface:
                sniff_kwargs["iface"] = self.iface
            pkts = sniff(**sniff_kwargs)
            self.sniffing_error = None
        except Exception as e:
            self.sniffing_error = str(e)
            print(f"Error sniffing interface: {e}. Falling back to empty flow batch.")
            pkts = []
        
        raw_packet_count = len(pkts)
        print(f"[live] captured {raw_packet_count} raw packets (iface={self.iface or 'default'})")
            
        if raw_packet_count == 0:
            # Return empty dataframe with correct columns
            df_empty = pd.DataFrame(columns=[
                'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Flow Bytes/s',
                'Flow Packets/s', 'Average Packet Size', 'SYN Flag Count', 'RST Flag Count',
                'PSH Flag Count', 'ACK Flag Count', 'src_ip', 'dst_ip', 'Protocol'
            ])
            return df_empty, [], 0
            
        df_flows = extract_flow_features(pkts)
        labels = []
        for idx, row in df_flows.iterrows():
            labels.append("BENIGN")  # default label for live packets, model will evaluate anomalies
            
        return df_flows, labels, raw_packet_count

    def _detect_aggregate_flood(self, df_batch):
        """Detect DDoS / SYN floods at the batch level.

        Tools like hping3 --flood generate thousands of tiny 1-packet SYN
        flows per second.  Each individual flow looks benign to the
        Isolation Forest (low packet count, low byte count).  This method
        inspects the *aggregate* batch statistics and flags every flow in
        the batch as anomalous when the pattern matches a volumetric flood.

        Returns:
            is_flood (bool): True if the batch looks like a flood.
            flood_label (str): Human-readable label for the attack type.
        """
        if len(df_batch) == 0:
            return False, ""
            
        # Ignore common local multicast noise when calculating flood heuristics
        if 'dst_ip' in df_batch.columns:
            ignore_mask = (
                ((df_batch['dst_ip'] == '224.0.0.251') & (df_batch['Destination Port'] == 5353)) |
                ((df_batch['dst_ip'] == '224.0.0.252') & (df_batch['Destination Port'] == 5355)) |
                ((df_batch['dst_ip'] == '239.255.255.250') & (df_batch['Destination Port'] == 1900))
            )
            df_eval = df_batch[~ignore_mask]
        else:
            df_eval = df_batch
            
        if len(df_eval) == 0:
            return False, ""

        total_flows = len(df_eval)
        total_syn = int(df_eval['SYN Flag Count'].sum())
        total_pkts = int(df_eval['Total Fwd Packets'].sum() + df_eval['Total Backward Packets'].sum())
        syn_only_flows = int(((df_eval['SYN Flag Count'] > 0) & (df_eval['ACK Flag Count'] == 0)).sum())
        one_pkt_flows = int((df_eval['Total Fwd Packets'] + df_eval['Total Backward Packets'] <= 2).sum())
        unique_ports = int(df_eval['Destination Port'].nunique())
        unique_dst_ips = int(df_eval.get('dst_ip', pd.Series()).nunique())

        # Heuristic 0: high number of unique destination ports/IPs hit rapidly is a fast port scan or sweep
        if total_flows >= 15 and ((unique_ports / total_flows) > 0.15 or (unique_dst_ips / total_flows) > 0.15):
            return True, "Potential Port Scan"

        # Heuristic 1: lots of SYN-only (no ACK) single-packet flows
        if total_flows >= 50 and syn_only_flows / total_flows > 0.6:
            return True, "Potential DDoS / SYN Flood"

        # Heuristic 2: very high flow count dominated by tiny flows
        if total_flows >= 50 and one_pkt_flows / total_flows > 0.7:
            return True, "Potential DDoS / Volumetric Flood"

        # Heuristic 3: extremely high aggregate SYN count
        if total_syn > 50:
            return True, "Potential DDoS / SYN Flood"

        # Heuristic 4: catch other volumetric floods (e.g. HTTP GET floods) where avg packets are low but traffic is extremely uniform
        if total_flows >= 50 and (total_pkts / total_flows) < 10 and (df_batch['Destination Port'] == 80).sum() / total_flows > 0.8:
            return True, "Potential DDoS / Volumetric Flood"

        return False, ""

    def run_loop(self):
        """Main execution loop that runs continuously, updating state files."""
        self.is_running = True
        total_packets_sniffed = 0
        total_anomalies_detected = 0
        
        # Write initial Running status so the dashboard can detect us
        robust_write_json(STATUS_FILE, {
            "status": "Running",
            "mode": self.active_mode,
            "run_mode": self.mode,
            "packet_rate": 0,
            "byte_rate": 0,
            "anomaly_rate": 0,
            "total_packets": 0,
            "total_anomalies": 0,
            "threat_score": 0
        })
        
        print("Starting live traffic anomaly detection pipeline...")
        
        while self.is_running:
            tick_start = time.time()
            
            # ── Check for stop signal FIRST, before any processing ──
            status_data = robust_read_json(STATUS_FILE, default={})
            if status_data.get("status") == "Stopped":
                print("Stop signal received from dashboard. Exiting loop.")
                self.is_running = False
                break
            # Pick up mode changes from the dashboard
            self.active_mode = status_data.get("mode", self.active_mode)
            
            # Track raw captured packet count (meaningful for live mode)
            raw_pkt_count = 0
            
            # 1. Fetch flow batch
            if self.mode == "live":
                df_batch, true_labels, raw_pkt_count = self.get_live_flow_sample()
            else:
                df_batch, true_labels = self.get_flow_sample()
            
            # 2. Run detector predictions
            predictions = []
            scores = []
            if len(df_batch) > 0:
                if self.model_loaded:
                    try:
                        preds, scs = self.detector.predict(df_batch)
                        scores = list(scs)
                        predictions = list(preds)
                        
                        # In live mode, flows are truncated to 1.5s, which can cause
                        # the model to flag normal traffic as anomalous with low confidence.
                        # Filter out low-confidence anomalies (scores close to 0)
                        if self.mode == "live":
                            for i in range(len(predictions)):
                                if predictions[i] == -1 and scores[i] >= -0.15:
                                    predictions[i] = 1 # Revert to normal
                                    
                    except Exception as e:
                        print(f"Prediction error: {e}")
                        # Fallback
                        predictions = [1] * len(df_batch)
                        scores = [0.1] * len(df_batch)
                else:
                    # Threshold-based detection fallback (when no model is loaded)
                    for idx, row in df_batch.iterrows():
                        # Refined fallback rules to minimize false positives on normal traffic
                        if row['Flow Packets/s'] > 50000 or row['SYN Flag Count'] > 100:
                            predictions.append(-1)
                            scores.append(-0.5)
                        elif row['Destination Port'] > 1024 and row['Total Fwd Packets'] <= 1 and row['SYN Flag Count'] > 0:
                            predictions.append(-1)
                            scores.append(-0.3)
                        else:
                            predictions.append(1)
                            scores.append(0.2)

            # 2b. Aggregate flood detection (catches hping3-style attacks)
            is_flood, flood_label = self._detect_aggregate_flood(df_batch)
            if is_flood and len(predictions) > 0:
                print(f"[WARNING] Aggregate flood detected: {flood_label} ({len(df_batch)} flows in batch)")
                # Override every prediction in the batch to anomaly
                predictions = [-1] * len(predictions)
                scores = [-0.6] * len(predictions)
                
            # Whitelist local multicast noise to prevent false positives
            for i in range(len(predictions)):
                row = df_batch.iloc[i]
                ip = str(row.get('dst_ip', ''))
                port = int(row.get('Destination Port', 0))
                if (ip == '224.0.0.251' and port == 5353) or (ip == '224.0.0.252' and port == 5355) or (ip == '239.255.255.250' and port == 1900):
                    predictions[i] = 1 # Revert to normal
                        
            # 3. Calculate statistics for this interval
            timestamp_str = datetime.now().strftime("%H:%M:%S")
            
            # Sum total packets and bytes across all flows in this batch
            batch_packet_count = int(df_batch['Total Fwd Packets'].sum() + df_batch['Total Backward Packets'].sum()) if len(df_batch) > 0 else 0
            batch_byte_count = int(df_batch['Total Length of Fwd Packets'].sum() + df_batch['Total Length of Bwd Packets'].sum()) if len(df_batch) > 0 else 0
            
            # For live mode, prefer the raw captured packet count when it's
            # higher than the flow-aggregated sum (each unique 5-tuple flow
            # may only show fwd_packets=1, understating volume)
            if self.mode == "live" and raw_pkt_count > batch_packet_count:
                batch_packet_count = raw_pkt_count
            
            # ── Convert to true per-second rates ──
            tick_elapsed = max(time.time() - tick_start, 0.1)  # guard against division by zero
            # For playback mode the batch represents ~1.5s of simulated traffic;
            # for live mode it represents the actual sniff window (~1.5s).
            tick_window = tick_elapsed if self.mode == "live" else 1.5
            packet_rate = int(batch_packet_count / tick_window)
            byte_rate = int(batch_byte_count / tick_window)
            
            # 4. Filter and Generate alerts
            new_alerts = []
            filtered_anomalies_count = 0
            
            for i, p in enumerate(predictions):
                if p == -1:
                    row = df_batch.iloc[i]
                    # Attempt to describe anomaly type
                    if is_flood:
                        anomaly_type = flood_label
                    elif (row['Total Fwd Packets'] + row.get('Total Backward Packets', 0) <= 5) and row.get('Flow Duration', 0) <= 500000:
                        anomaly_type = "Potential Port Scan"
                    elif row['Flow Packets/s'] > 2000 or row['SYN Flag Count'] > 50:
                        anomaly_type = "Potential DDoS / SYN Flood"
                    else:
                        anomaly_type = "Suspicious Connection"
                        
                    # Coordinated Detection Filtering
                    if self.active_mode == "PortScan" and "Port Scan" not in anomaly_type:
                        continue
                    if self.active_mode == "DDoS" and "DDoS" not in anomaly_type and "Flood" not in anomaly_type:
                        continue
                        
                    filtered_anomalies_count += 1
                        
                    alert = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "anomaly_type": anomaly_type,
                        "src_ip": str(row['src_ip']),
                        "dst_ip": str(row['dst_ip']),
                        "dst_port": int(row['Destination Port']),
                        "protocol": "TCP" if row['Protocol'] == 6 else ("UDP" if row['Protocol'] == 17 else "Other"),
                        "confidence": f"{min(99, int((1.0 - float(scores[i] + 0.5)) * 100))}%"
                    }
                    new_alerts.append(alert)
                    
            anomalies_in_batch = filtered_anomalies_count
            anomaly_ratio = anomalies_in_batch / len(predictions) if len(predictions) > 0 else 0
            
            total_packets_sniffed += batch_packet_count
            total_anomalies_detected += anomalies_in_batch
            
            # ── Threat score calculation ──
            # Base threat from anomaly ratio (0-100)
            base_threat = anomaly_ratio * 100
            
            # Rate booster: more responsive to moderate traffic volumes.
            # 500 pkts/sec already contributes noticeably; caps at 30 points.
            rate_booster = min(30, (packet_rate / 500) * 15)
            
            threat_score = min(100, int(base_threat + rate_booster))
            
            # When the aggregate flood detector fires, enforce a minimum threat
            # ONLY IF the current profile allows DDoS alerts!
            if is_flood and self.active_mode != "PortScan":
                threat_score = max(threat_score, 85)
                    
            # Update Alerts Log File (cap individual alerts per tick to avoid overwhelming the log)
            if new_alerts:
                try:
                    # Only keep the top 10 alerts from this tick to avoid flooding the log with
                    # thousands of identical DDoS rows
                    new_alerts = new_alerts[:10]
                    existing_alerts = robust_read_json(ALERTS_FILE, default=[])
                    
                    # Keep latest 100 alerts
                    updated_alerts = new_alerts + existing_alerts
                    updated_alerts = updated_alerts[:100]
                    
                    robust_write_json(ALERTS_FILE, updated_alerts)
                except Exception as e:
                    print(f"Error saving alerts: {e}")
                    
            # 5. Update History Log File
            try:
                existing_history = robust_read_json(HISTORY_FILE, default=[])
                        
                history_point = {
                    "time": timestamp_str,
                    "packet_rate": packet_rate,
                    "byte_rate": byte_rate,
                    "anomaly_count": anomalies_in_batch,
                    "anomaly_ratio": int(anomaly_ratio * 100),
                    "threat_score": threat_score
                }
                
                # Keep latest 30 points
                updated_history = existing_history + [history_point]
                updated_history = updated_history[-30:]
                
                robust_write_json(HISTORY_FILE, updated_history)
            except Exception as e:
                print(f"Error saving history: {e}")
                
            # 6. Update Live Status File — re-read to preserve any dashboard-written keys
            #    but NEVER write status=Running if someone set it to Stopped in between
            try:
                fresh_status = robust_read_json(STATUS_FILE, default=None)
                if fresh_status is not None:
                    if fresh_status.get("status") == "Stopped":
                        print("Stop signal detected before status write. Exiting.")
                        self.is_running = False
                        break
                    # FIX: Read the mode from UI in case it changed while we were sniffing
                    self.active_mode = fresh_status.get("mode", self.active_mode)
                else:
                    # File read completely failed (e.g. concurrent access issue). Skip writing this tick to be safe.
                    continue
                    
                status_point = {
                    "status": "Running",
                    "mode": self.active_mode,
                    "run_mode": self.mode,
                    "packet_rate": packet_rate,
                    "byte_rate": byte_rate,
                    "anomaly_rate": int(anomaly_ratio * 100),
                    "total_packets": total_packets_sniffed,
                    "total_anomalies": total_anomalies_detected,
                    "threat_score": threat_score
                }
                # Preserve sniffing_error if set
                if self.sniffing_error:
                    status_point["sniffing_error"] = self.sniffing_error
                robust_write_json(STATUS_FILE, status_point)
            except Exception as e:
                print(f"Error saving status: {e}")
                
            # Sleep between ticks (shorter if sniffing blocks for 1.5s)
            if self.mode == "live":
                time.sleep(0.1)
            else:
                time.sleep(1.5)
            
        print("Simulation loop ended.")
