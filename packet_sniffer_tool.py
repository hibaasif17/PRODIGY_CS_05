from scapy.all import sniff, IP, TCP, UDP
import sys

# Function to handle each packet
def handle_packet(packet):
    # Check if the packet contains an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Check for TCP or UDP and extract relevant information
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"
        else:
            src_port = dst_port = None
            protocol_name = "Other"

        # Print packet information
        print(f"Packet: {protocol_name} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Main function to start packet sniffing
def main(interface):
    print(f"Starting packet sniffing on {interface}...")
    # Start sniffing on the specified interface
    sniff(iface=interface, prn=handle_packet, store=0)

# Check if the script is being run directly
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python packet_sniffer.py <interface>")
        sys.exit(1)
    
    # Call the main function with the specified interface
    main(sys.argv[1])