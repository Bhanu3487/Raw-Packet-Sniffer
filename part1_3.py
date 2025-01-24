import scapy.all as scapy
import pandas as pd
from collections import defaultdict

# Output file names with .csv extension
pcap_file = "6.pcap"
output_file_src_flows = "part1_3_source_id_flows.csv"
output_file_dst_flows = "part1_3_destination_id_flows.csv"

# Initialize dictionaries to store the data
source_ip_flows = defaultdict(int)
destination_ip_flows = defaultdict(int)
src_dst_data_transferred = defaultdict(int)

# Read pcap file in chunks and process packets
def analyze_pcap_in_chunks(pcap_file, chunk_size=1000):
    global source_ip_flows, destination_ip_flows, src_dst_data_transferred
    
    # Open pcap file and process it in chunks
    packets = scapy.PcapReader(pcap_file)  # PcapReader reads the file incrementally
    
    while True:
        # Read a chunk of packets
        chunk = [packet for packet in packets.__iter__()][:chunk_size]
        
        if not chunk:
            break  # End of file
        
        # Process each packet in the chunk
        for packet in chunk:
            if packet.haslayer(scapy.IP):
                # Extract source and destination IP addresses
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                src_port = packet.sport if packet.haslayer(scapy.TCP) else None
                dst_port = packet.dport if packet.haslayer(scapy.TCP) else None

                # Count the number of flows for source and destination IPs
                source_ip_flows[src_ip] += 1
                destination_ip_flows[dst_ip] += 1

                # If the packet is TCP, count the data transferred between source-destination pairs
                if src_port and dst_port:
                    # Use a tuple of (source IP, source port, destination IP, destination port) as key
                    flow_pair = (src_ip, src_port, dst_ip, dst_port)
                    src_dst_data_transferred[flow_pair] += len(packet)  # Add the packet size to the corresponding flow pair

def save_dict_to_csv(filename, dictionary):
    # Convert defaultdict to regular dict before saving as CSV
    dictionary = dict(dictionary)
    
    # Convert the dictionary to a pandas DataFrame and save it to CSV
    df = pd.DataFrame(list(dictionary.items()), columns=["Key", "Value"])
    df.to_csv(filename, index=False)

def main():
    analyze_pcap_in_chunks(pcap_file)
    
    # Print and save the results for source IP flows
    print("Source IP Flows:")
    print(source_ip_flows)  # You might want to print a subset if the dictionary is large
    save_dict_to_csv(output_file_src_flows, source_ip_flows)
    
    # Print and save the results for destination IP flows
    print("Destination IP Flows:")
    print(destination_ip_flows)  # Again, consider printing a subset if necessary
    save_dict_to_csv(output_file_dst_flows, destination_ip_flows)
    
    # Find the source-destination pair with most data transferred
    if src_dst_data_transferred:  # Ensure there is data in the dictionary
        max_data_transfer_pair = max(src_dst_data_transferred, key=src_dst_data_transferred.get)
        max_data = src_dst_data_transferred[max_data_transfer_pair]

        print("\nSource-Destination pair with the most data transferred:")
        print(f"Source IP: {max_data_transfer_pair[0]}, Source Port: {max_data_transfer_pair[1]}, Destination IP: {max_data_transfer_pair[2]}, Destination Port: {max_data_transfer_pair[3]}")
        print(f"Total Data Transferred: {max_data} bytes")
    else:
        print("\nNo data transferred (no valid TCP packets with source-destination pairs).")

if __name__ == "__main__":
    main()
