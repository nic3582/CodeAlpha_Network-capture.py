from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.packet import Raw
import datetime

# Common ports
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT"
}


def identify_protocol(packet):
    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(DNS):
        return "DNS"

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        return COMMON_PORTS.get(tcp.dport) or COMMON_PORTS.get(tcp.sport) or "TCP"

    if packet.haslayer(UDP):
        udp = packet[UDP]
        return COMMON_PORTS.get(udp.dport) or COMMON_PORTS.get(udp.sport) or "UDP"

    return "OTHER"


def packet_callback(packet):

    print("=" * 90)
    print("Time:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    protocol = identify_protocol(packet)
    print("Protocol :", protocol)

    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"Source IP      : {ip.src}")
        print(f"Destination IP : {ip.dst}")
        print(f"TTL            : {ip.ttl}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"Source Port    : {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print("Transport      : TCP")

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"Source Port    : {udp.sport}")
        print(f"Destination Port: {udp.dport}")
        print("Transport      : UDP")

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print("ICMP Type      :", icmp.type)
        print("ICMP Code      :", icmp.code)

    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)

        print(f"Payload Size   : {len(data)} bytes")

        try:
            preview = data[:100].decode("utf-8", errors="replace")
            print("Payload Preview")
            print("-" * 40)
            print(preview)
            print("-" * 40)

        except:
            print("Binary Payload")

    print("Packet Length  :", len(packet), "bytes")


print("Listening for packets...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, store=False)