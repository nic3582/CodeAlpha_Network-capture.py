# CodeAlpha_Network-capture.pyOverview

This program is a network traffic monitoring tool developed in Python using the Scapy library. It captures packets traveling through a network interface in real time and displays useful information about each packet. It is intended for educational purposes, network troubleshooting, and analyzing traffic on networks you own or have permission to monitor.

Purpose

The main objective of the program is to:

Capture network packets in real time.
Identify the network protocol used by each packet.
Display source and destination IP addresses.
Show source and destination port numbers.
Display packet size and timestamp.
Provide a preview of the packet payload when available.
Help users understand how network communication works.
Features

The program is capable of:

Capturing live network traffic.
Detecting common protocols such as:
TCP
UDP
ICMP
DNS
HTTP (identified by common ports)
HTTPS (identified by common ports)
Displaying:
Capture time
Source IP address
Destination IP address
Source port
Destination port
Protocol name
Packet length
Payload preview (when present)
Running continuously until stopped by the user.
How the Program Works
The program initializes the Scapy library.
It begins listening for packets on the selected network interface.
Whenever a packet is detected, it is passed to a callback function.
The callback function examines the packet layers to determine the protocol.
It extracts important information such as IP addresses, ports, and payload.
The extracted information is displayed in a readable format on the terminal.
The program repeats this process for every packet captured until the user presses Ctrl + C.
Technologies Used
Programming Language: Python
Library: Scapy
Operating System: Windows (with Npcap) or Linux (with appropriate privileges)
Development Environment: Visual Studio Code
Applications

This program can be used for:

Learning computer networking concepts.
Understanding packet structure.
Monitoring traffic on a personal or authorized network.
Troubleshooting connectivity issues.
Supporting cybersecurity education and network administration.
Limitations
Encrypted traffic (such as HTTPS) cannot be read; only metadata such as IP addresses, ports, and packet sizes are visible.
On Windows, Npcap must be installed for packet capture.
Administrator (Windows) or root (Linux) privileges are typically required to capture packets.
The program analyzes packets as they are captured and does not perform advanced filtering or deep protocol analysis.
