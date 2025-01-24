# Metrics and PLots

import scapy.all as scapy
import matplotlib.pyplot as plt

# File path to the pcap file
pcap_file = "6.pcap"
output_image_file = "part1_1_packet_size_distribution.png"

# Initialize variables
total_data = 0
total_packets = 0
packet_sizes = []

# Read pcap file and process packets
def analyze_pcap(pcap_file):
    global total_data, total_packets, packet_sizes

    # Open pcap file and iterate through packets (iterating because pcap_file is very large)
    packets = scapy.rdpcap(pcap_file, count = 10)

    for packet in packets:
        total_packets += 1
        packet_size = len(packet)
        total_data += packet_size
        packet_sizes.append(packet_size)

    # Calculate the metrics
    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = total_data / total_packets

    return min_size, max_size, avg_size

# Save the histogram of packet sizes to a file
def save_packet_size_histogram(output_image_file):
    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=50, edgecolor="black")
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.grid(True)
    
    # Save the plot as a .png file
    plt.savefig(output_image_file)
    print(f"Histogram saved as: {output_image_file}")

# Main function
def main():
    min_size, max_size, avg_size = analyze_pcap(pcap_file)

    # Print metrics
    print(f"Total Packets: {total_packets}")
    print(f"Total Data Transferred: {total_data} bytes")
    print(f"Minimum Packet Size: {min_size} bytes")
    print(f"Maximum Packet Size: {max_size} bytes")
    print(f"Average Packet Size: {avg_size:.2f} bytes")

    # Save the histogram of packet sizes to a file
    save_packet_size_histogram(output_image_file)

if __name__ == "__main__":
    main()
