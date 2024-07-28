from scapy.all import *

# Protocol number to name mapping
protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}

def packet_analysis(packet):
    try:
        # Check if packet is IPv4
        if packet.haslayer(IP):
            # Get source and destination IP addresses
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            # Get protocol number
            protocol_num = packet[IP].proto
            # Map protocol number to name, or keep the number if not in the mapping
            protocol = protocol_names.get(protocol_num, protocol_num)

            # Check if Raw layer exists and get payload
            payload = packet[Raw].load if packet.haslayer(Raw) else ""

            # Print packet information
            print(f"Source IP: {source_ip}")
            print(f"Destination IP: {destination_ip}")
            print(f"Protocol: {protocol}")
            print(f"Payload: {payload}")
            print("--------------------------------")
    except Exception as e:
        print(f"An error occurred: {e}")

# Start sniffing
sniff(filter="ip", prn=packet_analysis)
