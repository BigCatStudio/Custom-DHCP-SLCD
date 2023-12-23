from scapy.all import sendp, get_if_raw_hwaddr, get_if_hwaddr, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import mac2str, str2mac


if __name__ == "__main__":
    conf.iface = "vt-green"
    conf.checkIPaddr = False
    fam, hw = get_if_raw_hwaddr(conf.iface)
    packet = Ether(src=hw, dst="ff:ff:ff:ff:ff:ff") / \
             IP(src="0.0.0.0", dst="255.255.255.255") / \
             UDP(sport=68, dport=67) / \
             BOOTP(chaddr=hw) / \
             DHCP(options=[("message-type", "discover"), "end"])
                
    sendp(packet, iface="vt-green")
    
    packet.show()
    print(f"\nMAC address (bytes): {hw}\n")
    
    formatted_mac = get_if_hwaddr(conf.iface)
    print(f"\nMAC address (string): {formatted_mac}\n") # TODO check if this address is same as in 'ip a -> interface'
    
