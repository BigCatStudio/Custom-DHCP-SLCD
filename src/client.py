from scapy.all import sendp, sniff, get_if_raw_hwaddr, get_if_hwaddr, conf, get_working_if
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread
from os import system


class DHCP_Client:
    def __init__(self, interface, mac_client):
        self.interface = interface
        self.mac_client = mac_client
        self.ip_client = "0.0.0.0"      # Initially interface does not have assigned IP address
        self.ip_offered = None

    def send_discover(self):
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255") / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=self.mac_client) / \
                 DHCP(options=[("message-type", "discover"), "end"])
        sendp(packet, iface=self.interface)
        # packet.show()   # Displays all elements of every layer of packet

    def send_request(self, ip_offered, ip_server):
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255") / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=self.mac_client) / \
                 DHCP(options=[('message-type', 'request'),
                               ("client_id", self.mac_client),
                               ("requested_addr", ip_offered),
                               ("server_id", ip_server), 'end'])
        sendp(packet, iface=self.interface)
        self.ip_offered = ip_offered

    def packet_handler(self, packet):
        if DHCP in packet:
            print(packet.summary())

            match packet[DHCP].options[0][1]:
                case 2:  # DHCP Offer
                    ip_offered = packet[BOOTP].yiaddr
                    print(f"Received DHCP Offer for IP address: {ip_offered}")
                    ip_server = packet['BOOTP'].siaddr
                    self.send_request(ip_offered, ip_server)
                case 5:  # DHCP ACK
                    if self.ip_offered == packet[BOOTP].yiaddr:
                        print(f"Received DHCP ACK for IP address: {self.ip_offered}")
                        system(f"ifconfig {self.interface} {self.ip_offered}/24")
                        self.ip_client = self.ip_offered
        # or p in ans: print p[1][Ether].src, p[1][IP].src

    def end_sniffing():
        print("Client is not sniffing")

    def __str__(self):
        output = "\nClient information\n" + \
                 f"Interface: {self.interface}\n" + \
                 f"MAC address (bytes): {self.mac_client}\n" + \
                 f"MAC address (string): {get_if_hwaddr(conf.iface)}\n" + \
                 f"IP address: {self.ip_client}"
        return output


if __name__ == "__main__":
    conf.checkIPaddr = False    # Has to be set for Discover because scapy sends response by matching IP (255.255.255.255 will never match DHCP server address)
    Client = DHCP_Client(conf.iface, get_if_raw_hwaddr(conf.iface)[1])

    thread_sniffing = Thread(
        target=lambda: sniff(
            filter='udp and (port 67 or 68)',
            prn=Client.packet_handler,
            # stop_filter=Client.end_sniffing,  # TODO think if client ever has to stop sniffing packets
            timeout=10  # TODO If prn will not be invoked in timeout thread will terminate -> maybe it should never terminate?
        ),
        name='thread_sniffing'
    )
    
    thread_sniffing.start()
    Client.send_discover()
    # sleep(0.25)
    thread_sniffing.join()

# TODO check when to resend Discover if server does not respond with Offer
# TODO check when to resend Request if server does not respond with Ack