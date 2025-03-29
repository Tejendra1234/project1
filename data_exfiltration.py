import scapy.all as scapy
from logger import store_in_csv

def detect_data_exfiltration(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        packet_size = len(packet)
        if packet_size > 1000:
            print(f"Potential Data Exfiltration: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}, Size: {packet_size} bytes")
            store_in_csv("Exfliteration", f"Potential Data Exfiltration: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}, Size: {packet_size} bytes")

def monitor_data_exfiltration(interface="Ethernet"):
    print("Monitoring for Data Exfiltration...")
    scapy.sniff(iface=interface, filter="tcp", prn=detect_data_exfiltration, store=0)