import pyshark
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Function to extract features from a Wireshark capture
def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    data = []

    for packet in cap:
        try:
            protocol = packet.highest_layer
            length = int(packet.length)
            src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            src_port = packet.tcp.srcport if hasattr(packet, 'tcp') else (
                packet.udp.srcport if hasattr(packet, 'udp') else 'N/A')
            dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else (
                packet.udp.dstport if hasattr(packet, 'udp') else 'N/A')
            timestamp = float(packet.sniff_timestamp)

            data.append([protocol, length, src_ip, dst_ip, src_port, dst_port, timestamp])
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    cap.close()
    return pd.DataFrame(data, columns=['Protocol', 'Length', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Timestamp'])


# Train a model to identify anomalies
def detect_anomalies(data):
    # Select numeric columns for training
    features = data[['Length', 'Timestamp']]

    # Normalize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    # Train an Isolation Forest model
    model = IsolationForest(contamination=0.05, random_state=42)
    data['Anomaly'] = model.fit_predict(scaled_features)

    return data


# Analyze anomalies and suggest reasons
def analyze_anomalies(data):
    anomalies = data[data['Anomaly'] == -1]
    for index, row in anomalies.iterrows():
        print(f"Abnormal Packet at Line {index + 1}: ")
        print(f"  Protocol: {row['Protocol']}")
        print(f"  Length: {row['Length']}")
        print(f"  Source: {row['Src_IP']}:{row['Src_Port']}")
        print(f"  Destination: {row['Dst_IP']}:{row['Dst_Port']}")

        # Suggest reasons for abnormalities
        if row['Length'] > 1500:
            print(
                "  Reason: Packet length exceeds typical MTU size (1500 bytes). Could indicate fragmentation or unusual payload.")
        elif row['Protocol'] == 'ICMP':
            print("  Reason: ICMP packets in high volume can indicate scanning or DoS activity.")
        elif row['Src_IP'] == 'N/A' or row['Dst_IP'] == 'N/A':
            print("  Reason: Missing IP information, possibly due to malformed packets.")
        else:
            print("  Reason: General anomaly detected.")


# Main execution
if __name__ == "__main__":
    pcap_file = input("Enter the path to the Wireshark capture file (.pcap): ")
    print("Extracting features from the capture file...")
    data = extract_features(pcap_file)

    print("Detecting anomalies in the capture...")
    analyzed_data = detect_anomalies(data)

    print("Analyzing anomalies...")
    analyze_anomalies(analyzed_data)

    # Save results to a CSV for further review
    output_file = "analyzed_capture.csv"
    analyzed_data.to_csv(output_file, index=False)
    print(f"Analysis complete. Results saved to {output_file}.")
