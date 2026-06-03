from scapy.all import sniff, IP, IPv6

def process_packet(packet):

    print("\n==============================")

    if packet.haslayer(IP):
        print("Protocol: IPv4")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

    elif packet.haslayer(IPv6):
        print("Protocol: IPv6")
        print("Source IP:", packet[IPv6].src)
        print("Destination IP:", packet[IPv6].dst)

    print("==============================")

print("Starting Network Sniffer...")
print("Capturing 20 packets...\n")

sniff(prn=process_packet, count=20)

print("\nCapture Completed!")
