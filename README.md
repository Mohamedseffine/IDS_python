# IDS Python

A lightweight Python-based intrusion detection system (IDS) built with Scapy and scikit-learn. The project captures TCP/IP traffic, extracts network-flow features, and evaluates them against a trained Random Forest classifier plus simple signature rules for common attacks such as SYN floods and port scans.

## What this project does

This project is designed as a proof-of-concept IDS for learning and experimentation. It does the following:

- Captures live packets from a network interface using Scapy
- Builds per-flow statistics for source/destination IPs and ports
- Extracts features like packet size, duration, packet rates, byte rates, TCP flags, and window size
- Uses a synthetic training dataset to train a supervised detector
- Applies signature-based rules for suspicious traffic patterns
- Logs alerts to `ids_alerts.log` in JSON format

## Project files

- `main.py` — core IDS implementation
- `test_ids.py` — smoke test and validation script
- `synthetic_training_data.csv` — labeled training data used by the Random Forest model
- `requirements.txt` — Python dependencies
- `ids_alerts.log` — generated alert log file

## How it works

The IDS is organized around four main components in `main.py`:

### 1. PacketCapture

`PacketCapture` uses Scapy's `sniff()` function to monitor network traffic on a given interface. Each packet is passed to a callback, and TCP/IP packets are pushed into a queue for processing.

### 2. TrafficAnalyzer

`TrafficAnalyzer` examines each packet and computes flow-level metrics:

- packet size
- flow duration
- packet rate
- byte rate
- TCP flags
- TCP window size
- SYN count for a destination
- unique destination ports per source

These values are used to detect suspicious behavior over a rolling time window.

### 3. Detection_Engine

`Detection_Engine` combines two detection methods:

- Signature-based detection rules:
  - `syn_flood`: triggers when a destination receives a high number of SYN requests in a short time
  - `port_scan`: triggers when a source probes multiple destination ports with short SYN packets
- Supervised detection:
  - Trains a `RandomForestClassifier` from the CSV dataset
  - Uses the classifier to determine whether traffic is likely malicious (`bad`) or normal (`good`)

### 4. AlertSystem and IntrusionDetectionSystem

`AlertSystem` writes alert records to `ids_alerts.log` with timestamps, IP information, confidence values, and threat details.

`IntrusionDetectionSystem` ties the components together and runs the full detection pipeline while packets are being captured.

## Training data

The model is trained using `synthetic_training_data.csv`, which contains labeled feature rows in the format:

- `packet_size`
- `flow_duration`
- `packet_rate`
- `byte_rate`
- `tcp_flags`
- `window_size`
- `label`

This makes the project easy to run and test without needing a real capture source.

## Requirements

The project uses Python packages listed in `requirements.txt`:

- scapy
- scikit-learn
- numpy
- scipy
- python-nmap
- joblib
- cloudpickle
- narwhals

## How to run it

### 1. Create and activate a virtual environment

```bash
cd /path/to/IDS_python
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the IDS

The program starts live packet capture on the default interface (`eth0`). In most Linux environments, this requires root privileges.

```bash
sudo ./venv/bin/python main.py
```

You can also customize the interface by editing the constructor in `main.py` or by creating a small runner script that calls:

```python
from main import IntrusionDetectionSystem
ids = IntrusionDetectionSystem(interface="eth0")
ids.start()
```

### 4. Run the test script

```bash
./venv/bin/python test_ids.py
```

This validates that the attack signatures and supervised classification behave as expected on synthetic traffic samples.

## Notes

- This is a learning-focused IDS prototype, not a production-grade security appliance.
- Live capture works only on an actual network interface and usually requires elevated permissions.
- For development or testing, the included smoke test demonstrates the expected threat detection behavior without needing a real network capture.
- Alerts are written to `ids_alerts.log` and can be reviewed after the IDS runs.

## Example output

When the detector sees a SYN flood or port scan, it will produce alert records in the log and print related threat information to the console.
