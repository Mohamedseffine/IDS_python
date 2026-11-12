from scapy.all import IP, TCP
from main import IntrusionDetectionSystem, TrafficAnalyzer

def test_ids():
    # Create test packets to simulate various scenarios
    test_packets = [
        # Normal traffic
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # A few SYN requests, below the flood threshold
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # Port scan simulation
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    ids = IntrusionDetectionSystem()
    for index, packet in enumerate(test_packets):
        packet.time = 1000.0 + index * 0.01

    normal_features = {
        'packet_size': 600,
        'flow_duration': 10.0,
        'packet_rate': 5.0,
        'byte_rate': 3000.0,
        'tcp_flags': 16,
        'window_size': 8192,
        'syn_count': 0,
        'unique_destination_ports': 1
    }
    threat_features = {
        'packet_size': 60,
        'flow_duration': 1.0,
        'packet_rate': 250.0,
        'byte_rate': 15000.0,
        'tcp_flags': 2,
        'window_size': 4096,
        'syn_count': 101,
        'unique_destination_ports': 3
    }
    assert not any(
        threat['type'] == 'supervised'
        for threat in ids.detection_engine.detect_threats(normal_features)
    )
    assert any(
        threat['type'] == 'supervised'
        for threat in ids.detection_engine.detect_threats(threat_features)
    )

    flood_analyzer = TrafficAnalyzer()
    flood_features = None
    for index in range(101):
        packet = (
            IP(src=f"10.0.0.{index + 1}", dst="192.168.1.2")
            / TCP(sport=50000 + index, dport=80, flags="S")
        )
        packet.time = 2000.0 + index * 0.005
        flood_features = flood_analyzer.analyze_packet(packet)

    flood_threats = ids.detection_engine.detect_threats(flood_features)
    assert any(
        threat.get('rule') == 'syn_flood'
        for threat in flood_threats
    )
    print("\nDetected a SYN flood: 101 SYNs to one destination within one second.")

    expired_packet = (
        IP(src="10.0.1.1", dst="192.168.1.2")
        / TCP(sport=60000, dport=80, flags="S")
    )
    expired_packet.time = 2002.0
    expired_features = flood_analyzer.analyze_packet(expired_packet)
    expired_threats = ids.detection_engine.detect_threats(expired_features)
    assert expired_features['syn_count'] == 1
    assert not any(
        threat.get('rule') == 'syn_flood'
        for threat in expired_threats
    )

    packet_features = [
        ids.traffic_analyzer.analyze_packet(packet)
        for packet in test_packets
    ]
    assert packet_features[-1]['unique_destination_ports'] == 3
    port_scan_threats = ids.detection_engine.detect_threats(packet_features[-1])
    assert any(
        threat.get('rule') == 'port_scan'
        for threat in port_scan_threats
    )

    # Simulate packet processing and threat detection
    print("Starting IDS Test...")
    for i, (packet, features) in enumerate(
        zip(test_packets, packet_features), 1
    ):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        if features:
            # Detect threats based on features
            threats = ids.detection_engine.detect_threats(features)

            if threats:
                print(f"Detected threats: {threats}")
            else:
                print("No threats detected.")
        else:
            print("Packet does not contain IP/TCP layers or is ignored.")

    print("\nIDS Test Completed.")

if __name__ == "__main__":
    test_ids()