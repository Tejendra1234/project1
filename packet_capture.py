import pyshark

def capture_packets(interface="Ethernet", filter="ip"):
    print(f"Capturing packets on {interface} with filter {filter}")
    cap = pyshark.LiveCapture(interface=interface, display_filter=filter)
    cap.sniff(timeout=60)  # Capture for 60 seconds
    for packet in cap:
        print(packet)                                                                               