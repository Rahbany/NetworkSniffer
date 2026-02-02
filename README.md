# Python Network Sniffer

## Overview
This Python project captures and analyzes live TCP, UDP, and ICMP traffic using Scapy. The tool displays detailed packet information in real time, including source/destination IPs, ports, packet size, and timestamp, and logs all data to a CSV file. Suspicious repeated traffic is flagged automatically. 

---

## Features
- Real-time packet capture with timestamped display
- Protocol counts with percentages and average packet size
- Detection of repeated/suspicious TCP and ICMP packets
- Identification of top 3 sender IPs
- CSV logging for detailed packet analysis
- Command-line options for protocol filtering, packet count, and log filename

---

## Requirements
- Python 3.10+
- Scapy (`pip install scapy`)
- Npcap installed (Windows) for packet capture

---

## Usage
1. Run the sniffer from the terminal:
   ```bash
   python sniffer.py --count 50 --protocol ALL --log packet_log.csv
