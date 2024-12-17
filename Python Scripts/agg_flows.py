import pyshark
import pandas as pd
from datetime import datetime
import numpy as np
from cleaning import clean_data


#Function to aggregate packets into flow-level features
def aggregate_packets(df_packets):
    #Convert timestamp to datetime
    df_packets['time'] = pd.to_datetime(df_packets['time'])

    #Aggregate packets into Flow-Level Features

    #Convert timestamp to datetime if needed (already done in extraction step)
    #Group packets into flows based oncommon features (IP Addresses, Ports, Protocols)
    flow_groups = df_packets.groupby(['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol'])

    flows = []
    print("Starting flow aggregation...")

    #Iterate over each flow group to calculate aggregated features
    #TCP flag counts are calculated based on flag presence in each packet
    for (src_ip, dst_ip, src_port, dst_port, protocol), group in flow_groups:
        flow_duration = (group['time'].max() - group['time'].min()).total_seconds()
        total_fwd_packets = len(group[group['source_ip'] == src_ip])
        total_bwd_packets = len(group[group['source_ip'] == dst_ip])
        total_length_fwd_packets = group[group['source_ip'] == src_ip]['packet_length'].sum()
        total_length_bwd_packets = group[group['source_ip'] == dst_ip]['packet_length'].sum()
        
        flow_data = {
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Source Port': src_port,
            'Destination Port': dst_port,
            'Protocol': protocol,
            'Flow Duration': (group['time'].max() - group['time'].min()).total_seconds(),
            'Total Fwd Packets': len(group[group['source_ip'] == src_ip]),
            'Total Backward Packets': len(group[group['source_ip'] == dst_ip]),
            'Fwd Packet Length Max': group[group['source_ip'] == src_ip]['packet_length'].max(),
            'Fwd Packet Length Min': group[group['source_ip'] == src_ip]['packet_length'].min(),
            'Fwd Packet Length Mean': group[group['source_ip'] == src_ip]['packet_length'].mean(),
            'Fwd Packet Length Std': group[group['source_ip'] == src_ip]['packet_length'].std(ddof=0),
            'Bwd Packet Length Max': group[group['source_ip'] == dst_ip]['packet_length'].max(),
            'Bwd Packet Length Min': group[group['source_ip'] == dst_ip]['packet_length'].min(),
            'Bwd Packet Length Mean': group[group['source_ip'] == dst_ip]['packet_length'].mean(),
            'Bwd Packet Length Std': group[group['source_ip'] == dst_ip]['packet_length'].std(ddof=0),
            'Packet Length Mean': group['packet_length'].mean(),
            'Packet Length Std': group['packet_length'].std(ddof=0),
            'Packet Length Variance': group['packet_length'].var(ddof=0),
            'Flow IAT Mean': group['time'].diff().mean().total_seconds() if len(group) > 1 else 0,
            'Flow IAT Std': group['time'].diff().std().total_seconds() if len(group) > 1 else 0,
            'Flow IAT Max': group['time'].diff().max().total_seconds() if len(group) > 1 else 0,
            'Flow IAT Min': group['time'].diff().min().total_seconds() if len(group) > 1 else 0,
            'Fwd IAT Total': group[group['source_ip'] == src_ip]['time'].diff().sum().total_seconds() if len(group[group['source_ip'] == src_ip]) > 1 else 0,
            'Fwd IAT Mean': group[group['source_ip'] == src_ip]['time'].diff().mean().total_seconds() if len(group[group['source_ip'] == src_ip]) > 1 else 0,
            'Fwd IAT Std': group[group['source_ip'] == src_ip]['time'].diff().std().total_seconds() if len(group[group['source_ip'] == src_ip]) > 1 else 0,
            'Fwd IAT Max': group[group['source_ip'] == src_ip]['time'].diff().max().total_seconds() if len(group[group['source_ip'] == src_ip]) > 1 else 0,
            'Fwd IAT Min': group[group['source_ip'] == src_ip]['time'].diff().min().total_seconds() if len(group[group['source_ip'] == src_ip]) > 1 else 0,
            'Bwd IAT Total': group[group['source_ip'] == dst_ip]['time'].diff().sum().total_seconds() if len(group[group['source_ip'] == dst_ip]) > 1 else 0,
            'Bwd IAT Mean': group[group['source_ip'] == dst_ip]['time'].diff().mean().total_seconds() if len(group[group['source_ip'] == dst_ip]) > 1 else 0,
            'Bwd IAT Std': group[group['source_ip'] == dst_ip]['time'].diff().std().total_seconds() if len(group[group['source_ip'] == dst_ip]) > 1 else 0,
            'Bwd IAT Max': group[group['source_ip'] == dst_ip]['time'].diff().max().total_seconds() if len(group[group['source_ip'] == dst_ip]) > 1 else 0,
            'Bwd IAT Min': group[group['source_ip'] == dst_ip]['time'].diff().min().total_seconds() if len(group[group['source_ip'] == dst_ip]) > 1 else 0,
            'FIN Flag Count': group['tcp_flags'].apply(lambda x: '0x01' in str(x)).sum(),
            'SYN Flag Count': group['tcp_flags'].apply(lambda x: '0x02' in str(x)).sum(),
            'RST Flag Count': group['tcp_flags'].apply(lambda x: '0x04' in str(x)).sum(),
            'PSH Flag Count': group['tcp_flags'].apply(lambda x: '0x08' in str(x)).sum(),
            'ACK Flag Count': group['tcp_flags'].apply(lambda x: '0x010' in str(x)).sum(),
            'URG Flag Count': group['tcp_flags'].apply(lambda x: '0x20' in str(x)).sum(),
            'ECE Flag Count': group['tcp_flags'].apply(lambda x: '0x40' in str(x)).sum(),
            'CWE Flag Count': group['tcp_flags'].apply(lambda x: '0x80' in str(x)).sum(),
            'Fwd Header Length': group[group['source_ip'] == src_ip]['header_length'].sum(),
            'Bwd Header Length': group[group['source_ip'] == dst_ip]['header_length'].sum(),
            'Init Fwd Win Bytes': group[group['source_ip'] == src_ip]['window_size'].iloc[0] if len(group[group['source_ip'] == src_ip]) > 0 else 0,
            'Fwd Packets/s': len(group[group['source_ip'] == src_ip]) / ((group['time'].max() - group['time'].min()).total_seconds() + 1e-9),
            'Bwd Packets/s': len(group[group['source_ip'] == dst_ip]) / ((group['time'].max() - group['time'].min()).total_seconds() + 1e-9),
            'Flow Bytes/s': (group['packet_length'].sum()) / ((group['time'].max() - group['time'].min()).total_seconds() + 1e-9),
            'Fwd Avg Bytes/Bulk': total_length_fwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0,
            'Bwd Avg Bytes/Bulk': total_length_bwd_packets / total_bwd_packets if total_bwd_packets > 0 else 0,
            'Fwd Packets Length Total': total_length_fwd_packets,
            'Bwd Packets Length Total': total_length_bwd_packets,
            'Flow Packets/s': (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0,
            'Down/Up Ratio': total_length_bwd_packets / total_length_fwd_packets if total_length_fwd_packets > 0 else 0,
            'Subflow Fwd Packets': total_fwd_packets,
            'Subflow Bwd Packets': total_bwd_packets,
            'Subflow Fwd Bytes': total_length_fwd_packets,
            'Subflow Bwd Bytes': total_length_bwd_packets,
            'Avg Packet Size': (total_length_fwd_packets + total_length_bwd_packets) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0,
            'Fwd Act Data Packets': total_fwd_packets,
            'Active Mean': group['time'].diff().mean().total_seconds() if len(group) > 1 else 0,
            'Active Std': group['time'].diff().std().total_seconds() if len(group) > 1 else 0,
            'Active Max': group['time'].diff().max().total_seconds() if len(group) > 1 else 0,
            'Active Min': group['time'].diff().mean().total_seconds() if len(group) > 1 else 0,
            'Idle Mean': group['time'].diff().mean().total_seconds() if len(group) > 1 else 0,
            'Idle Std': group['time'].diff().std().total_seconds() if len(group) > 1 else 0,
            'Idle Max': group['time'].diff().max().total_seconds() if len(group) > 1 else 0,
            'Idle Min': group['time'].diff().min().total_seconds() if len(group) > 1 else 0,
            'Fwd PSH Flags': group['tcp_flags'].apply(lambda x: '0x08' in str(x)).sum(),
            'Bwd PSH Flags': group['tcp_flags'].apply(lambda x: '0x08' in str(x)).sum(),
            'Fwd URG Flags': group['tcp_flags'].apply(lambda x: '0x20' in str(x)).sum(),
            'Bwd URG Flags': group['tcp_flags'].apply(lambda x: '0x20' in str(x)).sum(),
            'Init Bwd Win Bytes': group[group['source_ip'] == dst_ip]['window_size'].iloc[0] if len(group[group['source_ip'] == dst_ip]) > 0 else 0,
            'Avg Bwd Segment Size': total_length_bwd_packets / total_bwd_packets if total_bwd_packets > 0 else 0,
            'Avg Fwd Segment Size': total_length_fwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0,
            'Packet Length Min': group['packet_length'].min(),
            'Packet Length Max': group['packet_length'].max(),
            'Fwd Avg Packets/Bulk': total_fwd_packets / flow_duration if flow_duration > 0 else 0,
            'Bwd Avg Bulk Rate': total_length_bwd_packets / flow_duration if flow_duration > 0 else 0,
            'Bwd Avg Packets/Bulk': total_bwd_packets / flow_duration if flow_duration > 0 else 0,
            'Fwd Avg Bulk Rate': total_length_fwd_packets / flow_duration if flow_duration > 0 else 0,
            'Fwd Seg Size Min': group[group['source_ip'] == src_ip]['packet_length'].min() if len(group[group['source_ip'] == src_ip]) > 0 else 0,
        }
        flows.append(flow_data)

    #Convert aggregated flow data into a DataFrame
    df_flows = pd.DataFrame(flows)
    print(f"Aggregated {len(df_flows)} flows.")
    print(df_flows.head())

    #Call the cleaning function to clean the aggregated data
    cleaned_data = clean_data(df_flows)

    #Instead of saving the flow data, pass it towards cleaning
    send_to_model(cleaned_data)

def send_to_model(cleaned_data):
    import requests
    headers = {'Content-Type': 'application/json'}
    url = 'http://127.0.0.1:5001/predict'

    #Iterate through each flow to make predictions
    for _, flow in cleaned_data.iterrows():
        flow_json = flow.to_json()
        response = requests.pst(url, headers=headers, json=flow_json)

        if response.status_code == 200:
            print(f"Prediction Response: {response.json()}")
        else:
            print(f"Error: Failed to get prediction. Status code: {response.status_code}")

#Save aggregated flows to CSV for analysis through ML
#df_flows.to_csv('aggregated_flows.csv', index=False)

#Save flows as Parquet for model
#df_flows.to_parquet('aggregated_flows.parquet', index=False)

#print("Flow Aggregation Completed. :D")