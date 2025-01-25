import scapy.all as scapy
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict

class PacketAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packet_sizes = []
        self.source_ip_flows = defaultdict(int)
        self.destination_ip_flows = defaultdict(int)
        self.src_dst_data_transferred = defaultdict(int)
        self.unique_pairs = set()

    def analyze_packets(self):
        try:
            with scapy.PcapReader(self.pcap_file) as pcap:
                for packet in pcap:
                    # Question 1: Extract packet size
                    packet_size = len(packet)
                    self.packet_sizes.append(packet_size)

                    # Question 3: Count flows for source and destination IPs
                    if packet.haslayer(scapy.IP):
                        src_ip = packet[scapy.IP].src
                        dst_ip = packet[scapy.IP].dst

                        self.source_ip_flows[src_ip] += 1
                        self.destination_ip_flows[dst_ip] += 1

                        # Track data transferred between specific pairs
                        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                            src_port = packet.sport if packet.haslayer(scapy.TCP) else None
                            dst_port = packet.dport if packet.haslayer(scapy.TCP) else None
                            if src_port and dst_port:
                                flow_pair = (src_ip, src_port, dst_ip, dst_port)
                                self.src_dst_data_transferred[flow_pair] += packet_size

                        # Question 2: Track unique source-destination pairs
                        if packet.haslayer(scapy.TCP):
                            src_port = packet[scapy.TCP].sport
                            dst_port = packet[scapy.TCP].dport
                        elif packet.haslayer(scapy.UDP):
                            src_port = packet[scapy.UDP].sport
                            dst_port = packet[scapy.UDP].dport
                        else:
                            continue  # Skip non-TCP/UDP packets

                        self.unique_pairs.add(((src_ip, src_port), (dst_ip, dst_port)))

        except Exception as e:
            print(f"Error reading pcap file: {e}")

    def get_packet_metrics(self):
        total_packets = len(self.packet_sizes)
        total_data = sum(self.packet_sizes)
        min_size = min(self.packet_sizes) if self.packet_sizes else 0
        max_size = max(self.packet_sizes) if self.packet_sizes else 0
        avg_size = total_data / total_packets if total_packets > 0 else 0
        return total_data, total_packets, min_size, max_size, avg_size


class QuestionOne:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def display_packet_metrics(self):
        total_data, total_packets, min_size, max_size, avg_size = self.analyzer.get_packet_metrics()
        print(f"Total Data Transferred: {total_data} bytes")
        print(f"Total Packets Transferred: {total_packets}")
        print(f"Minimum Packet Size: {min_size} bytes")
        print(f"Maximum Packet Size: {max_size} bytes")
        print(f"Average Packet Size: {avg_size:.2f} bytes")

    def save_packet_size_histogram(self, output_file):
        plt.figure(figsize=(10, 6))
        plt.hist(self.analyzer.packet_sizes, bins=50, edgecolor="black")
        plt.title('Packet Size Distribution')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.grid(True)
        plt.savefig(output_file)
        print(f"Histogram saved as: {output_file}")


class QuestionTwo:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def save_unique_pairs(self, output_file):
        with open(output_file, 'w') as file:
            for pair in self.analyzer.unique_pairs:
                file.write(f"Source: {pair[0][0]}:{pair[0][1]} -> Destination: {pair[1][0]}:{pair[1][1]}\n")
        print(f"Unique source-destination pairs saved to {output_file}")


class QuestionThree:
    def __init__(self, analyzer):
        self.analyzer = analyzer

    def save_flows_to_csv(self, output_file_src, output_file_dst):
        # Save source flows
        df_src = pd.DataFrame(list(self.analyzer.source_ip_flows.items()), columns=["Source IP", "Flows"])
        df_src.to_csv(output_file_src, index=False)
        print("Total flows by all the sources are saved to part1_3_source_ip_flows.csv")

        # Save destination flows
        df_dst = pd.DataFrame(list(self.analyzer.destination_ip_flows.items()), columns=["Destination IP", "Flows"])
        df_dst.to_csv(output_file_dst, index=False)
        print("Total flows to all the destinations are saved to part1_3_destination_ip_flows.csv")

    def display_max_data_transfer_pair(self):
        if self.analyzer.src_dst_data_transferred:
            max_data_transfer_pair = max(self.analyzer.src_dst_data_transferred, key=self.analyzer.src_dst_data_transferred.get)
            max_data = self.analyzer.src_dst_data_transferred[max_data_transfer_pair]
            print("\nSource-Destination pair with the most data transferred:")
            print(f"Source IP: {max_data_transfer_pair[0]}, Source Port: {max_data_transfer_pair[1]}, "
                  f"Destination IP: {max_data_transfer_pair[2]}, Destination Port: {max_data_transfer_pair[3]}")
            print(f"Total Data Transferred: {max_data} bytes")


# Main function to tie everything together
def main():
    pcap_file = "6.pcap"
    analyzer = PacketAnalyzer(pcap_file)
    print("Analysing packets...")
    analyzer.analyze_packets()  # Single iteration over the packets

    # Question 1
    print("\npart1: question 1")
    q1 = QuestionOne(analyzer)
    q1.display_packet_metrics()
    q1.save_packet_size_histogram("part1_1_packet_size_distribution.png")

    # Question 2
    print("\npart1: question 2")
    q2 = QuestionTwo(analyzer)
    q2.save_unique_pairs("part1_2_unique_source_destination_pairs.txt")

    # Question 3
    print("\npart1: question 3")
    q3 = QuestionThree(analyzer)
    q3.save_flows_to_csv("part1_3_source_ip_flows.csv", "part1_3_destination_ip_flows.csv")
    q3.display_max_data_transfer_pair()


if __name__ == "__main__":
    main()
