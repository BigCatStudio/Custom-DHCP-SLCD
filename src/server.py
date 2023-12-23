from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP


def packet_handler(packet):
    if DHCP in packet:
        print(packet.summary())
# or p in ans: print p[1][Ether].src, p[1][IP].src

if __name__ == "__main__":
    packet = sniff(iface="vt-green", filter="udp and (port 67 or port 68)", prn=packet_handler)
    print(packet)


# TODO check what are the timeouts for holding IP address for client if client does not respond with Request etc 
# TODO Hold IP addresses for lease time -> how to do it?