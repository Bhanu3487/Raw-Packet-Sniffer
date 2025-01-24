import scapy.all as scapy
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict

# File path to the pcap file
pcap_file = "6.pcap"
output_file_image = "part1_1_packet_size_distribution.png"
output_file_src_flows = "part1_3_source_ip_flows.csv"
output_file_dst_flows = "part1_3_destination_ip_flows.csv"
output_file_unique_pairs = "part1_2_unique_source_destination_pairs.txt"

# Initialize dictionaries to store data
source_ip_flows = defaultdict(int)
destination_ip_flows = defaultdict(int)
src_dst_data_transferred = defaultdict(int)
packet_sizes = []
unique_pairs = set()

# Stream the pcap file and process each packet
def analyze_pcap(pcap_file):
    global source_ip_flows, destination_ip_flows, src_dst_data_transferred, packet_sizes, unique_pairs

    # Open pcap file and stream packets
    try:
        with scapy.PcapReader(pcap_file) as pcap:
            for packet in pcap:
                # Check if the packet has an IP layer (IPv4 or IPv6)
                if packet.haslayer(scapy.IP):
                    # Extract IP addresses
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    packet_size = len(packet)
                    packet_sizes.append(packet_size)

                    # Count data for source IP and destination IP flows
                    source_ip_flows[src_ip] += 1
                    destination_ip_flows[dst_ip] += 1

                    # If the packet has a transport layer (TCP/UDP), calculate transferred data
                    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                        src_port = packet.sport if packet.haslayer(scapy.TCP) else None
                        dst_port = packet.dport if packet.haslayer(scapy.TCP) else None
                        if src_port and dst_port:
                            flow_pair = (src_ip, src_port, dst_ip, dst_port)
                            src_dst_data_transferred[flow_pair] += packet_size

                    # Track unique source-destination pairs (IP:port)
                    if packet.haslayer(scapy.TCP):
                        src_port = packet[scapy.TCP].sport
                        dst_port = packet[scapy.TCP].dport
                    elif packet.haslayer(scapy.UDP):
                        src_port = packet[scapy.UDP].sport
                        dst_port = packet[scapy.UDP].dport
                    else:
                        continue  # Skip packets without transport layer (e.g., ICMP)

                    pair = ((src_ip, src_port), (dst_ip, dst_port))
                    unique_pairs.add(pair)

    except Exception as e:
        print(f"Error reading pcap file: {e}")

# Calculate metrics
def calculate_packet_metrics():
    total_packets = len(packet_sizes)
    total_data = sum(packet_sizes)
    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = total_data / total_packets if total_packets > 0 else 0
    return total_data, total_packets, min_size, max_size, avg_size

# Save packet size histogram
def save_packet_size_histogram():
    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=50, edgecolor="black")
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.grid(True)
    plt.savefig(output_file_image)
    print(f"Histogram saved as: {output_file_image}")

# Save data to CSV
def save_dict_to_csv(filename, dictionary):
    df = pd.DataFrame(list(dictionary.items()), columns=["Key", "Value"])
    df.to_csv(filename, index=False)

# Save unique pairs to file
def save_unique_pairs():
    with open(output_file_unique_pairs, 'w') as file:
        for pair in unique_pairs:
            file.write(f"Source: {pair[0][0]}:{pair[0][1]} -> Destination: {pair[1][0]}:{pair[1][1]}\n")
    print(f"Unique source-destination pairs saved to {output_file_unique_pairs}")

# Main function to tie everything together
def main():
    # Analyze the pcap file
    analyze_pcap(pcap_file)
    
    # Calculate and print metrics
    total_data, total_packets, min_size, max_size, avg_size = calculate_packet_metrics()
    print(f"Total Packets: {total_packets}")
    print(f"Total Data Transferred: {total_data} bytes")
    print(f"Minimum Packet Size: {min_size} bytes")
    print(f"Maximum Packet Size: {max_size} bytes")
    print(f"Average Packet Size: {avg_size:.2f} bytes")

    # Save the histogram plot
    save_packet_size_histogram()

    # Save flow data to CSV
    save_dict_to_csv(output_file_src_flows, source_ip_flows)
    save_dict_to_csv(output_file_dst_flows, destination_ip_flows)

    # Find and print the source-destination pair with the most data transferred
    if src_dst_data_transferred:
        max_data_transfer_pair = max(src_dst_data_transferred, key=src_dst_data_transferred.get)
        max_data = src_dst_data_transferred[max_data_transfer_pair]
        print("\nSource-Destination pair with the most data transferred:")
        print(f"Source IP: {max_data_transfer_pair[0]}, Source Port: {max_data_transfer_pair[1]}, Destination IP: {max_data_transfer_pair[2]}, Destination Port: {max_data_transfer_pair[3]}")
        print(f"Total Data Transferred: {max_data} bytes")

    # Save unique source-destination pairs to file
    save_unique_pairs()

if __name__ == "__main__":
    main()
