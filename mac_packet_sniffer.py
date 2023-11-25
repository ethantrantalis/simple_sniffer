from scapy.all import sniff, Ether, IP, TCP, UDP

def process_packet(packet):
    # Check if it is an Ethernet packet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print("\nEthernet Header:")
        print(f"Source MAC: {eth.src}, Destination MAC: {eth.dst}, Type: {eth.type}")

    # Check if it's an IP packet
    if packet.haslayer(IP):
        ip = packet[IP]
        print("IP Header:")
        print(f"Source IP: {ip.src}, Destination IP: {ip.dst}, Protocol: {ip.proto}")

    # Check for TCP segment
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("TCP Segment:")
        print(f"Source Port: {tcp.sport}, Destination Port: {tcp.dport}, Sequence Number: {tcp.seq}, Acknowledgment: {tcp.ack}")

    # Check for UDP datagram
    if packet.haslayer(UDP):
        udp = packet[UDP]
        print("UDP Datagram:")
        print(f"Source Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}")

# Start sniffing packets in an infinite loop
sniff(prn=process_packet, store=False)