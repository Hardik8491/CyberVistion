from scapy.all import sniff, IP
import requests

def process_packet(packet):
    # Extract important data from the packet
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    protocol = packet.proto if packet.haslayer(IP) else None

    # Check for specific conditions (e.g., suspicious IPs, protocols)
    if src_ip and dst_ip:
        print(f"Threat detected: {src_ip} -> {dst_ip} using protocol {protocol}")
        # Send data to Django API endpoint for further analysis
        requests.post('http://127.0.0.1:8000/api/create-threat/', json={
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
        })

# Start sniffing packets
sniff(prn=process_packet, store=0)
