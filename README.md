
# Wireshark Capture Anomaly Detection

This Python script analyzes Wireshark `.pcap` files to detect and highlight abnormalities in network traffic using machine learning. It extracts features from the capture, detects anomalies with an Isolation Forest model, and provides insights into potential reasons for the abnormalities.

## Features

- **Feature Extraction**: Extracts key features from `.pcap` files, including:
  - Protocol type
  - Packet length
  - Source and destination IPs and ports
  - Timestamp
- **Anomaly Detection**: Utilizes the Isolation Forest algorithm to detect anomalies in network traffic.
- **Detailed Analysis**: Highlights abnormal packets and suggests potential reasons, such as:
  - Excessive packet length
  - ICMP floods
  - Malformed packets
- **CSV Output**: Saves the results to a CSV file for further analysis.

## Prerequisites

Ensure you have Python 3.7+ installed on your system. Install the required Python libraries:

```bash
pip install pyshark pandas scikit-learn
```

## Usage

1. Clone this repository or download the script.
2. Run the script using the following command:

   ```bash
   python wireshark_abnormal_analysis.py
   ```

3. Enter the path to your `.pcap` file when prompted:

   ```bash
   Enter the path to the Wireshark capture file (.pcap): /path/to/your/capture_file.pcap
   ```

4. The script will:
   - Extract features from the `.pcap` file.
   - Detect anomalies in the traffic.
   - Analyze and print the details of abnormal packets.
   - Save the analysis results to `analyzed_capture.csv` in the current directory.

## Example Output

When anomalies are detected, the script prints details like:

```plaintext
Abnormal Packet at Line 25: 
  Protocol: TCP
  Length: 2000
  Source: 192.168.1.1:443
  Destination: 192.168.1.2:55234
  Reason: Packet length exceeds typical MTU size (1500 bytes). Could indicate fragmentation or unusual payload.
```

## Output File

The results are saved in a CSV file named `analyzed_capture.csv`. This file includes all captured packets and an `Anomaly` column:

- `1`: Normal packet
- `-1`: Abnormal packet

## Customization

You can adjust the following parameters to tailor the script to your needs:

- **Contamination Rate**: Modify the `contamination` parameter in the Isolation Forest model to change the sensitivity of anomaly detection.
- **Feature Selection**: Adjust the features used for analysis in the `detect_anomalies` function.

## Known Limitations

- The script provides basic anomaly detection and may not identify advanced attacks or sophisticated patterns.
- Additional feature engineering or custom models may be required for specific use cases.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contribution

Contributions are welcome! Feel free to fork the repository, create issues, or submit pull requests to improve the script.

---

For any questions or feedback, please contact [mayank_nauni@mymail.sutd.edu.sg].
