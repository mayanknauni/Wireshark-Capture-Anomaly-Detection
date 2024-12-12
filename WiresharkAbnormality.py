import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Function to extract features from a Wireshark capture file
def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    data = []

    for packet in cap:
        try:
            protocol = packet.highest_layer

            # Skip specific Layer 2 protocols
            if protocol in ['STP', 'ARP', 'CDP']:
                continue

            length = int(packet.length)
            src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            src_port = packet.tcp.srcport if hasattr(packet, 'tcp') else (
                packet.udp.srcport if hasattr(packet, 'udp') else 'N/A')
            dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else (
                packet.udp.dstport if hasattr(packet, 'udp') else 'N/A')
            timestamp = float(packet.sniff_timestamp)

            # Check for TCP retransmissions and reset flags
            retransmission = False
            reset_flag = False
            if hasattr(packet, 'tcp'):
                retransmission = hasattr(packet.tcp, 'analysis_retransmission')
                reset_flag = packet.tcp.flags_reset == '1' if hasattr(packet.tcp, 'flags_reset') else False

            # Include additional information for L2 protocols
            if src_ip == 'N/A' and dst_ip == 'N/A':
                src_mac = packet.eth.src if hasattr(packet, 'eth') else 'N/A'
                dst_mac = packet.eth.dst if hasattr(packet, 'eth') else 'N/A'
                data.append(
                    [protocol, length, src_mac, dst_mac, src_port, dst_port, timestamp, retransmission, reset_flag])
            else:
                data.append(
                    [protocol, length, src_ip, dst_ip, src_port, dst_port, timestamp, retransmission, reset_flag])
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    cap.close()
    return pd.DataFrame(data, columns=['Protocol', 'Length', 'Src_Address', 'Dst_Address', 'Src_Port', 'Dst_Port',
                                       'Timestamp', 'Retransmission', 'Reset_Flag'])


# Function to detect anomalies using Isolation Forest
def detect_anomalies(data):
    # Select numeric features for analysis
    features = data[['Length', 'Timestamp']]

    # Normalize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    # Fit Isolation Forest model
    model = IsolationForest(contamination=0.05, random_state=42)
    data['Anomaly'] = model.fit_predict(scaled_features)

    # Add anomaly type
    data['Anomaly_Type'] = 'Other'
    data.loc[data['Retransmission'], 'Anomaly_Type'] = 'Retransmission'
    data.loc[data['Reset_Flag'], 'Anomaly_Type'] = 'Reset Flag'
    data.loc[(data['Length'] > 1500) & (data['Anomaly'] == -1), 'Anomaly_Type'] = 'High Packet Length'

    # Subdivide 'Other' anomalies into more detailed categories
    data.loc[(data['Anomaly_Type'] == 'Other') & (
                data['Timestamp'] > data['Timestamp'].quantile(0.95)), 'Anomaly_Type'] = 'High Latency'
    data.loc[(data['Anomaly_Type'] == 'Other') & (
        data['Protocol'].str.contains('UNKNOWN', na=False)), 'Anomaly_Type'] = 'Unexpected Protocol'
    data.loc[(data['Anomaly_Type'] == 'Other') & (
                (data['Src_Address'] == 'N/A') | (data['Dst_Address'] == 'N/A')), 'Anomaly_Type'] = 'Malformed Packet'

    return data


# Function to analyze and describe anomalies
def analyze_anomalies(data):
    anomalies = data[data['Anomaly'] == -1]
    for index, row in anomalies.iterrows():
        print(f"Abnormal Packet at Line {index + 1}:")
        print(f"  Protocol: {row['Protocol']}")
        print(f"  Length: {row['Length']} bytes")
        print(f"  Source: {row['Src_Address']}:{row['Src_Port']}")
        print(f"  Destination: {row['Dst_Address']}:{row['Dst_Port']}")
        print(f"  Anomaly Type: {row['Anomaly_Type']}")

        if row['Retransmission']:
            print("  Issue: Retransmission detected.")
            print("  Tip: Check for network congestion or packet loss.")
        if row['Reset_Flag']:
            print("  Issue: TCP Reset flag observed.")
            print("  Tip: Verify application behavior and potential connection issues.")
        if row['Anomaly_Type'] == 'High Latency':
            print("  Reason: Packet timing suggests unusually high latency.")
            print("  Tip: Investigate potential network congestion or overloaded servers.")
        if row['Anomaly_Type'] == 'Unexpected Protocol':
            print("  Reason: Detected protocol is unexpected or unknown.")
            print("  Tip: Validate protocol usage and ensure no misconfigurations or unauthorized traffic.")
        if row['Anomaly_Type'] == 'Malformed Packet':
            print("  Reason: Malformed packet with missing or invalid address information.")
            print("  Tip: Inspect capture details for errors or corrupted data.")


# Function to plot anomalies
def plot_anomalies(data):
    plt.figure(figsize=(12, 8))

    # Separate normal and abnormal packets
    normal_packets = data[data['Anomaly'] == 1]
    abnormal_packets = data[data['Anomaly'] == -1]

    # Plot normal packets
    plt.scatter(normal_packets.index, normal_packets['Length'], color='blue', label='Normal Packets')

    # Highlight abnormal packets with retransmissions and reset flags
    retransmissions = abnormal_packets[abnormal_packets['Retransmission']]
    resets = abnormal_packets[abnormal_packets['Reset_Flag']]
    high_latency = abnormal_packets[abnormal_packets['Anomaly_Type'] == 'High Latency']
    unexpected_protocol = abnormal_packets[abnormal_packets['Anomaly_Type'] == 'Unexpected Protocol']
    malformed_packet = abnormal_packets[abnormal_packets['Anomaly_Type'] == 'Malformed Packet']

    plt.scatter(retransmissions.index, retransmissions['Length'], color='orange', label='Retransmissions')
    plt.scatter(resets.index, resets['Length'], color='red', label='Reset Flags')
    plt.scatter(high_latency.index, high_latency['Length'], color='green', label='High Latency')
    plt.scatter(unexpected_protocol.index, unexpected_protocol['Length'], color='purple', label='Unexpected Protocol')
    plt.scatter(malformed_packet.index, malformed_packet['Length'], color='brown', label='Malformed Packet')

    plt.title('Packet Length vs. Index with Highlighted Anomalies')
    plt.xlabel('Packet Index')
    plt.ylabel('Packet Length')
    plt.legend()
    plt.show()


# Main function
if __name__ == "__main__":
    pcap_file = input("Enter the path to the Wireshark capture file (.pcap): ")
    print("\n[1] Extracting features from the capture file...")
    data = extract_features(pcap_file)

    print("\n[2] Detecting anomalies in the capture...")
    analyzed_data = detect_anomalies(data)

    print("\n[3] Analyzing anomalies...")
    analyze_anomalies(analyzed_data)

    print("\n[4] Plotting anomalies...")
    plot_anomalies(analyzed_data)

    # Save only anomalies to a CSV for further review
    output_file = "analyzed_capture.csv"
    anomalies = analyzed_data[analyzed_data['Anomaly'] == -1]
    anomalies.to_csv(output_file, index=False)
    print(f"\nAnalysis complete. Results saved to {output_file}.")
