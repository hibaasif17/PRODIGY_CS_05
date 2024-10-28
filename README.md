# Packet Sniffer Tool

This packet sniffer tool captures network traffic and inspects packets sent and received over a network. It is a useful tool for monitoring and analyzing network communication for educational purposes, network diagnostics, or ethical hacking.

## Features

- Captures incoming and outgoing packets on a network.
- Extracts and logs information from different network layers (Ethernet, IP, TCP, UDP, etc.).
- Displays packet source and destination addresses, protocols, and ports.
- Optionally logs packet data to a file for further analysis.

## Requirements

Before running the packet sniffer, ensure that the following requirements are met:

- **Python 3.x** (for Python implementation)
- **Administrative privileges** to capture packets (root access on Linux/macOS or running as Administrator on Windows)

### Required Libraries (for Python implementation)
If you're using Python, install the necessary libraries using `pip`:

```bash
pip install scapy
