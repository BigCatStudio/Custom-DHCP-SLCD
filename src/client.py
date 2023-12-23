from scapy.all import sendp, sniff, get_if_raw_hwaddr, get_if_hwaddr, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread


class DHCP_Client:
    def __init__(self, interface, mac_client):
        self.interface = interface
        self.mac_client = mac_client
        self.ip_client = "0.0.0.0"      # Initially interface does not have assigned IP address

    def packet_handler(self, packet):
        if DHCP in packet:
            print(packet.summary())

            match packet[DHCP].options[0][1]:
                case 2:  # DHCP Offer
                    print(f'Received DHCP Offer for IP address: {packet[BOOTP].yiaddr}')
                    # cli_mac = pkt['Ether'].dst
                    # serv_addr, off_addr = pkt['BOOTP'].siaddr, pkt[BOOTP].yiaddr
                    # offered_ip = off_addr
                    # send_request(cli_mac, off_addr, serv_addr)
                case 5:  # DHCP ACK
                    print(f'Received DHCP ACK for IP address: {packet[BOOTP].yiaddr}')
                    # serv_mac, cli_mac = pkt[Ether].src, pkt[Ether].dst
                    # serv_addr, cli_addr = pkt[BOOTP].siaddr, pkt[BOOTP].yiaddr
                    # iface = get_working_if().network_name
                    # system(f'ifconfig {iface} {cli_addr}/24')
                    # test_icmp(cli_mac, cli_addr, serv_mac, serv_addr)
        # or p in ans: print p[1][Ether].src, p[1][IP].src

    def end_sniffing():
        print("Client is not sniffing")

    def send_discover(self):
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
             IP(src="0.0.0.0", dst="255.255.255.255") / \
             UDP(sport=68, dport=67) / \
             BOOTP(chaddr=self.mac_client) / \
             DHCP(options=[("message-type", "discover"), "end"])

        sendp(packet, iface=self.interface)
        # packet.show()   # Displays all elements of every layer of packet

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