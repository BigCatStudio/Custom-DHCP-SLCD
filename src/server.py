from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP


def packet_handler(packet):
    if DHCP in packet:
        print(packet.summary())


if __name__ == "__main__":
    packet = sniff(iface="vt-blue", filter="udp and (port 67 or port 68)", prn=packet_handler)
    print(packet)
