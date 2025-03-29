import scapy.all as scapy
import re
from logger import store_in_csv

def extract_credentials(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors='ignore')
        matches = re.findall(r'(username|password)=(\S+)', payload)
        if matches:
            print(f"Credentials Found: {matches}")
            store_in_csv("credential found", matches)

def monitor_traffic_for_credentials(interface="Ethernet"):
    print("Monitoring for unencrypted HTTP credentials...")
    # Update the filter to capture HTTP packets (port 80)
    scapy.sniff(iface=interface, filter="tcp", prn=extract_credentials, store=0)