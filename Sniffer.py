from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv

# Dictionaries to track packet counts and sizes
protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
protocol_size = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
tcp_count = {}
icmp_count = {}
top_talkers = {}

# CSV log file
csv_file = "packet_log.csv"

# Initialize CSV
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Protocol", "Source", "Destination", "SrcPort", "DstPort", "Size"])

def analyze_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "OTHER"
        src_port = dst_port = ""
        size = len(packet)
        info = ""

        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_count['TCP'] += 1
            protocol_size['TCP'] += size
            tcp_count[src] = tcp_count.get(src, 0) + 1
            if tcp_count[src] > 10:
                info += f" ⚠ Suspicious TCP activity from {src}"

        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_count['UDP'] += 1
            protocol_size['UDP'] += size

        elif packet.haslayer(ICMP):
            proto = "ICMP"
            protocol_count['ICMP'] += 1
            protocol_size['ICMP'] += size
            icmp_count[src] = icmp_count.get(src, 0) + 1
            if icmp_count[src] > 5:
                info += f" ⚠ Suspicious ICMP from {src}"

        # Track top talkers
        top_talkers[src] = top_talkers.get(src, 0) + 1

        # Print live info
        if proto != "OTHER":
            print(f"{proto} packet: {src}:{src_port} -> {dst}:{dst_port}, size={size}{info}")

        # Log to CSV
        with open(csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([proto, src, dst, src_port, dst_port, size])

def main():
    print("Starting packet capture...")
    sniff(count=50, prn=analyze_packet, store=0)

    print("\nPacket Summary:")
    total_packets = sum(protocol_count.values())
    print("---------------------------")
    for proto in ['TCP', 'UDP', 'ICMP']:
        count = protocol_count[proto]
        percent = (count / total_packets * 100) if total_packets else 0
        avg_size = (protocol_size[proto] / count) if count else 0
        print(f"{proto}: {count} packets ({percent:.1f}%), Avg size: {avg_size:.1f} bytes")

    # Top talkers
    if top_talkers:
        top_src = max(top_talkers, key=top_talkers.get)
        print(f"Top sender IP: {top_src} with {top_talkers[top_src]} packets")

if __name__ == "__main__":
    main()
