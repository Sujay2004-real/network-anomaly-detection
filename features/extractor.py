import time
import pandas as pd
import numpy as np
from scapy.layers.inet import IP, TCP, UDP

def extract_flow_features(packets):
    """Aggregates a list of Scapy packets into flow-level records.
    
    Returns:
        pd.DataFrame containing the 13 required feature columns.
    """
    flows = {}
    
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
            
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        # Get ports
        sport = 0
        dport = 0
        tcp_flags = None
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            
        pkt_len = len(pkt)
        pkt_time = float(pkt.time)
        
        # Define flow key: (src_ip, sport, dst_ip, dport, proto)
        # Note: to capture bidirectional flows, we group them where src/dst can be flipped
        key1 = (src_ip, sport, dst_ip, dport, proto)
        key2 = (dst_ip, dport, src_ip, sport, proto)
        
        if key1 in flows:
            flow_key = key1
            direction = 'fwd'
        elif key2 in flows:
            flow_key = key2
            direction = 'bwd'
        else:
            flow_key = key1
            direction = 'fwd'
            # If the source port is a well-known service port and destination port is ephemeral,
            # it is likely a response packet. The true destination port of the service is sport.
            flow_dst_port = sport if (sport < 1024 and dport >= 1024) else dport
            flows[flow_key] = {
                'start_time': pkt_time,
                'end_time': pkt_time,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_len': 0,
                'bwd_len': 0,
                'total_len': 0,
                'syn_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'ack_count': 0,
                'dst_port': flow_dst_port,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto
            }
            
        flow = flows[flow_key]
        flow['end_time'] = pkt_time
        flow['total_len'] += pkt_len
        
        if direction == 'fwd':
            flow['fwd_packets'] += 1
            flow['fwd_len'] += pkt_len
        else:
            flow['bwd_packets'] += 1
            flow['bwd_len'] += pkt_len
            
        # Parse TCP flags
        if tcp_flags is not None:
            # tcp_flags can be an int or a string (e.g. 'S', 'A')
            flags_str = str(tcp_flags)
            if 'S' in flags_str:
                flow['syn_count'] += 1
            if 'R' in flags_str:
                flow['rst_count'] += 1
            if 'P' in flags_str:
                flow['psh_count'] += 1
            if 'A' in flags_str:
                flow['ack_count'] += 1
                
    # Build dataframe
    flow_records = []
    for key, flow in flows.items():
        duration_sec = flow['end_time'] - flow['start_time']
        duration_us = duration_sec * 1000000.0  # Microseconds (as in CICIDS)
        
        total_pkts = flow['fwd_packets'] + flow['bwd_packets']
        
        if duration_sec > 0:
            flow_bytes_sec = flow['total_len'] / duration_sec
            flow_pkts_sec = total_pkts / duration_sec
        else:
            flow_bytes_sec = np.inf
            flow_pkts_sec = np.inf
        avg_pkt_size = flow['total_len'] / total_pkts if total_pkts > 0 else 0
        
        record = {
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'Protocol': flow['protocol'],
            # The 13 model features:
            'Destination Port': flow['dst_port'],
            'Flow Duration': duration_us,
            'Total Fwd Packets': flow['fwd_packets'],
            'Total Backward Packets': flow['bwd_packets'],
            'Total Length of Fwd Packets': flow['fwd_len'],
            'Total Length of Bwd Packets': flow['bwd_len'],
            'Flow Bytes/s': flow_bytes_sec,
            'Flow Packets/s': flow_pkts_sec,
            'Average Packet Size': avg_pkt_size,
            'SYN Flag Count': flow['syn_count'],
            'RST Flag Count': flow['rst_count'],
            'PSH Flag Count': flow['psh_count'],
            'ACK Flag Count': flow['ack_count']
        }
        flow_records.append(record)
        
    if not flow_records:
        return pd.DataFrame(columns=['src_ip', 'dst_ip', 'Protocol'] + [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Flow Bytes/s',
            'Flow Packets/s', 'Average Packet Size', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count'
        ])
        
    return pd.DataFrame(flow_records)
