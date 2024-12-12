#Wireshark Capture Anomaly Detection

This Python script analyzes Wireshark .pcap files to detect and highlight abnormalities in network traffic using machine learning. It extracts features from the capture, detects anomalies with an Isolation Forest model, and provides insights into potential reasons for the abnormalities.

Features

Extracts key features from .pcap files, such as:

Protocol type

Packet length

Source and destination IPs and ports

Timestamp

Detects anomalies using the Isolation Forest algorithm.

Highlights abnormal packets and suggests potential reasons for the anomalies (e.g., excessive packet length, ICMP floods, malformed packets).

Outputs results to a CSV file for further analysis.

Prerequisites

Ensure you have Python 3.7+ installed on your system. The following Python libraries are required:

pyshark

pandas

scikit-learn

You can install these dependencies using the following command:

pip install pyshark pandas scikit-learn

Usage

Clone this repository or download the script.

Run the script using the following command:

python wireshark_abnormal_analysis.py

Enter the path to your .pcap file when prompted:

Enter the path to the Wireshark capture file (.pcap): /path/to/your/capture_file.pcap

The script will:

Extract features from the .pcap file.

Detect anomalies in the traffic.

Analyze and print the details of the abnormal packets.

Save the analysis results to analyzed_capture.csv in the current directory.

Example Output

When anomalies are detected, the script prints details like:

Abnormal Packet at Line 25:
  Protocol: TCP
  Length: 2000
  Source: 192.168.1.1:443
  Destination: 192.168.1.2:55234
  Reason: Packet length exceeds typical MTU size (1500 bytes). Could indicate fragmentation or unusual payload.

Output File

The results are saved in a CSV file named analyzed_capture.csv. This file includes all the captured packets and an Anomaly column:

1: Normal packet

-1: Abnormal packet

Customization

You can adjust the following:

Contamination Rate: Change the contamination parameter in the IsolationForest model to fine-tune anomaly detection sensitivity.

Feature Selection: Modify the features used for analysis in the detect_anomalies function.

Known Limitations

The script provides basic anomaly detection and may not identify advanced attacks or sophisticated patterns.

Additional feature engineering may be required for specific use cases.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Contribution

Feel free to fork the repository, create issues, or submit pull requests to improve the script.

