# Read and Parse pcap Files
from scapy.all import Raw, rdpcap

packets = rdpcap('6.pcap', count = 10)

# Fallback to print raw data if dissection fails
for i, packet in enumerate(packets):
    try:
        print(f"Packet {i+1}: {packet.summary()}")
    except Exception:
        print(f"Packet {i+1}: Raw data: {bytes(packet)}")
