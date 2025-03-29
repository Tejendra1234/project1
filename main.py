import argparse
from packet_capture import capture_packets
from arp_detection import monitor_arp
from data_exfiltration import monitor_data_exfiltration
from credential_extraction import monitor_traffic_for_credentials

def main():
    parser = argparse.ArgumentParser(description="Network Forensic Analysis Tool")
    parser.add_argument("-i", "--interface", help="Network Interface", default="Ethernet")
    parser.add_argument("-m", "--mode", help="Detection mode: capture, arp, exfiltration, credentials", required=True)
    args = parser.parse_args()
    
    if args.mode == "capture":
        capture_packets(args.interface)
    elif args.mode == "arp":
        monitor_arp(args.interface)
    elif args.mode == "exfiltration":
        monitor_data_exfiltration(args.interface)
    elif args.mode == "credentials":
        monitor_traffic_for_credentials(args.interface)
    else:
        print("Invalid mode! Choose from: capture, arp, exfiltration, credentials")

if __name__ == "__main__":
    main()