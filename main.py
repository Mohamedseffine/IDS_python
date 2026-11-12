from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import csv
from pathlib import Path
import threading
import queue


class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()


    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _:self.start_capture().is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(slef):
        self.stop_capture().set()
        self.capture_thread().join()



class TrafficAnalyzer:
    window_seconds = 1.0

    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count':0,
            'byte_count':0,
            'start_time':None,
            'last_time':None
        })
        self.syn_events_by_target = defaultdict(deque)
        self.scan_events_by_source = defaultdict(deque)

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src= packet[IP].src
            ip_dst = packet[IP].dst
            port_src= packet[TCP].sport
            port_dst = packet[TCP].dport
            current_time = float(packet.time)
            tcp_flags = int(packet[TCP].flags)

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)

            if stats['start_time'] is None:
                stats['start_time'] = current_time

            stats['last_time'] = current_time

            syn_events = self.syn_events_by_target[(ip_dst, port_dst)]
            scan_events = self.scan_events_by_source[ip_src]
            self._remove_expired_events(syn_events, current_time)
            self._remove_expired_events(scan_events, current_time)

            is_syn_request = tcp_flags & 0x02 and not tcp_flags & 0x10
            if is_syn_request:
                syn_events.append((current_time, ip_src))
                scan_events.append((current_time, port_dst))

            features = self.extract_features(packet, stats)
            features['syn_count'] = len(syn_events)
            features['unique_destination_ports'] = len({
                destination_port for _, destination_port in scan_events
            })
            return features

    def _remove_expired_events(self, events, current_time):
        cutoff = current_time - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()


    def extract_features(self, packet, stats):
        return {
    'packet_size': len(packet),
    'flow_duration': stats['last_time'] - stats['start_time'],
    'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time'])
                   if (stats['last_time'] - stats['start_time']) != 0 else stats['packet_count'],
    'byte_rate': stats['byte_count'] / (stats['last_time'] - stats['start_time'])
                 if (stats['last_time'] - stats['start_time']) != 0 else stats['byte_count'],
    'tcp_flags': int(packet[TCP].flags),
    'window_size': packet[TCP].window
}   




from sklearn.ensemble import RandomForestClassifier


class Detection_Engine:
    feature_columns = (
        'packet_size',
        'flow_duration',
        'packet_rate',
        'byte_rate',
        'tcp_flags',
        'window_size'
    )

    def __init__(self):
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            class_weight='balanced',
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['syn_count'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    (features['tcp_flags'] & 0x02) != 0 and
                    (features['tcp_flags'] & 0x10) == 0 and
                    features['unique_destination_ports'] >= 3
                )
            }
        }

    def train_supervised_detector(self, feature_rows, labels):
        if len(feature_rows) != len(labels):
            raise ValueError("Each training feature row must have one label.")
        if set(labels) != {'good', 'bad'}:
            raise ValueError("Training labels must include both 'good' and 'bad'.")

        self.classifier.fit(feature_rows, labels)
        self.is_trained = True

    def train_from_csv(self, training_data_path):
        path = Path(training_data_path)
        feature_rows = []
        labels = []

        with path.open(newline='', encoding='utf-8') as training_file:
            reader = csv.DictReader(training_file)
            required_columns = (*self.feature_columns, 'label')
            missing_columns = set(required_columns) - set(reader.fieldnames or ())
            if missing_columns:
                missing = ', '.join(sorted(missing_columns))
                raise ValueError(f"{path} is missing required columns: {missing}")

            for line_number, row in enumerate(reader, start=2):
                try:
                    feature_rows.append([
                        float(row[column]) for column in self.feature_columns
                    ])
                except (TypeError, ValueError) as error:
                    raise ValueError(
                        f"{path}:{line_number} contains an invalid feature value."
                    ) from error

                label = row['label'].strip().lower()
                if label not in {'good', 'bad'}:
                    raise ValueError(
                        f"{path}:{line_number} label must be 'good' or 'bad'."
                    )
                labels.append(label)

        if not feature_rows:
            raise ValueError(f"{path} contains no training rows.")

        self.train_supervised_detector(feature_rows, labels)

    def feature_vector(self, features):
        return [float(features[column]) for column in self.feature_columns]


    def detect_threats(self, features):
        if not self.is_trained:
            raise RuntimeError(
                "Train the supervised detector with labeled good and bad "
                "traffic before detecting threats."
            )

        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule':rule_name,
                    'confidence':1.0
                })



        # Supervised detection
        feature_vector = [self.feature_vector(features)]
        probabilities = self.classifier.predict_proba(feature_vector)[0]
        bad_index = list(self.classifier.classes_).index('bad')
        bad_confidence = float(probabilities[bad_index])
        if bad_confidence >= 0.5:
            threats.append({
                'type': 'supervised',
                'label': 'bad',
                'confidence': bad_confidence
            })

        return threats 



import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)


        handler= logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now(),
            'threattype':threat['type'],
            'source_ip':packet_info.get('source_ip'),
            'destination_ip':packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details':threat
        }

        self.logger.warning(json.dumps(alert))


        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )




class IntrusionDetectionSystem:

    def __init__(self, interface="eth0", training_data_path=None):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = Detection_Engine()
        if training_data_path is None:
            training_data_path = Path(__file__).with_name(
                "synthetic_training_data.csv"
            )
        self.detection_engine.train_from_csv(training_data_path)
        self.alert_system = AlertSystem()

        self.interface = interface


    def start(self):
        print(f"starting IDS on interface: {self.interface}")

        self.packet_capture.start_capture(self.interface)

        while True :
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    threats =  self.detection_engine.detect_threats(features)

                    for threat in threats :
                        packet_info = {
                            'source_ip':packet[IP].src,
                            'destination_ip':packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }

                        self.alert_system.generate_alert(threat, packet_info)
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print('Stopping IDS...')
                self.packet_capture.stop()
                break

if __name__ == '__main__':
    ids = IntrusionDetectionSystem()
    ids.start()
