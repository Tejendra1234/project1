import scapy.all as scapy
from scapy.layers.l2 import ARP
import requests
from logger import store_in_csv

# Maintain a mapping of legitimate IP-to-MAC addresses
ip_mac_mapping = {}

def detect_arp_poisoning(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        # Check if the IP is already in the mapping
        if ip in ip_mac_mapping:
            # Compare the MAC address with the known MAC address
            if ip_mac_mapping[ip] != mac:
                print(f"ARP Poisoning Detected! IP: {ip} is now claiming MAC: {mac} (Expected MAC: {ip_mac_mapping[ip]})")
                store_in_csv("ARP Poisoning", f"IP: {ip} is now claiming MAC: {mac} (Expected MAC: {ip_mac_mapping[ip]})")
                try:
                    requests.post("https://ntfy.sh/tejaserver1234",
                                  data=f"ARP Poisoning Detected! IP: {ip} is now claiming MAC: {mac} (Expected MAC: {ip_mac_mapping[ip]})".encode(encoding='utf-8'))
                except Exception as e:
                    print(f"Failed to send notification: {e}")
        else:
            # Add the new IP-to-MAC mapping
            ip_mac_mapping[ip] = mac

def monitor_arp(interface="Ethernet"):
    print("Monitoring ARP packets for MITM attacks...")
    scapy.sniff(iface=interface, filter="arp", prn=detect_arp_poisoning, store=0)