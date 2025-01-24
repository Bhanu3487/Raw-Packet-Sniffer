import scapy.all as scapy

# File path to the pcap file
pcap_file = "6.pcap"

# Set to store unique source-destination pairs
unique_pairs = set()

# Read pcap file and process packets
def find_unique_pairs(pcap_file):
    global unique_pairs

    # Open pcap file and iterate through packets
    packets = scapy.rdpcap(pcap_file, count = 10)

    for packet in packets:
        # Check if the packet has an IP layer (IPv4 or IPv6)
        if packet.haslayer(scapy.IP):
            # Extract source and destination IP addresses
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Check if the packet has a transport layer (TCP/UDP)
            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
            else:
                continue  # Skip packets without transport layer (e.g., ICMP)

            # Create a unique (source IP:port, destination IP:port) pair
            pair = ((src_ip, src_port), (dst_ip, dst_port))
            
            # Add the pair to the set
            unique_pairs.add(pair)

# Main function
def main():
    # Find unique source-destination pairs in the pcap file
    find_unique_pairs(pcap_file)

    # Print the unique pairs
    print(f"Unique Source-Destination Pairs:")
    for pair in unique_pairs:
        src, dst = pair
        print(f"Source: {src[0]}:{src[1]} -> Destination: {dst[0]}:{dst[1]}")

if __name__ == "__main__":
    main()
