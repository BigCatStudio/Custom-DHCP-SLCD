from scapy.all import sendp, sniff, get_if_raw_hwaddr, get_if_hwaddr, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread
from os import system


class DHCP_Server_Info:
    def __init__(self, mac_address, ip_address, host_name, subnet_mask, broadcast_address):
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.host_name = host_name
        self.subnet_mask = subnet_mask
        self.broadcast_address = broadcast_address

    def __str__(self):
        return "\nAssociated DHCP server info:" + \
               f"\n\t{self.mac_address}" + \
               f"\n\t{self.ip_address}" + \
               f"\n\t{self.host_name}" + \
               f"\n\t{self.subnet_mask}" + \
               f"\n\t{self.broadcast_address}\n"


def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options


class DHCP_Client:
    def __init__(self, interface, mac_client):
        self.host_name = "client-" + str(interface)
        self.interface = interface
        self.mac_client = mac_client
        self.ip_client = "0.0.0.0"      # Initially interface does not have assigned IP address
        self.ip_offered = None
        self.Server_Info = None     # TODO Initialized when all informations are retrieved in DHCP Offer

    def send_discover(self):
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255", ttl=64) / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=self.mac_client) / \
                 DHCP(options=[("message-type", "discover"),
                               ("hostname", self.host_name),
                               ("param_req_list", [1, 12, 28]), "end"])
        sendp(packet, iface=self.interface)
        print(f"\n{packet.summary()}")
        print("Sent DHCP Discovery")
        # TODO make availabilty to define TTl for user when creating client -> make thta for all options
        # maybe use json file for initial parameters for dhcp client and server like: { ip: [ttl:64] }

    def send_request(self, ip_server):
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255", ttl=64) / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=self.mac_client) / \
                 DHCP(options=[("message-type", "request"),
                               ("hostname", self.host_name),
                               ("requested_addr", self.ip_offered),
                               ("server_id", ip_server),    # TODO think if it is needed
                               ("param_req_list", [1, 12, 28]), "end"])
        sendp(packet, iface=self.interface)
        print(f"\n{packet.summary()}")
        print(f"Sent DHCP Request for IP: {self.ip_offered}")
        # TODO identyfing client and server should be done based on hostname and ip
        # server -> (hostname, server_id)
        # client -> (hostname, client_id)
        # client should contain information about session with every server and identify messages with it like defined in upper lines
        # same for server (it will exchange messages with many clients)

    def packet_handler(self, packet):
        if DHCP in packet:
            print(f"\n{packet.summary()}")
            match get_option_value(packet[DHCP].options, "message-type"):
                case 2:  # DHCP Offer
                    # TODO check if offered IP is valid -> regex
                    ip_server = packet["BOOTP"].siaddr
                    self.ip_offered = packet[BOOTP].yiaddr
                    self.Server_Info = DHCP_Server_Info(packet[Ether].src,
                                                        get_option_value(packet[DHCP].options, "server_id"),
                                                        get_option_value(packet[DHCP].options, "hostname"),
                                                        get_option_value(packet[DHCP].options, "subnet_mask"),
                                                        get_option_value(packet[DHCP].options, "broadcast_address"))
                    print(f"Received DHCP Offer for IP address: {self.ip_offered}")
                    self.send_request(ip_server)
                case 5:  # DHCP ACK
                    # TODO checking if ACK is received from server that you have info from DHCP Offer
                    if self.ip_offered == packet[BOOTP].yiaddr:
                        print(f"Received DHCP ACK for IP address: {self.ip_offered}")
                        system(f"ifconfig {self.interface} {self.ip_offered}/24")   # TODO instead of 24 -> subnet mask length
                        self.ip_client = self.ip_offered

    def end_sniffing():
        print("Client is not sniffing")

    def __str__(self):
        output = "\nClient info:\n" + \
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
            filter="udp and (port 67 or 68)",
            prn=Client.packet_handler,
            # stop_filter=Client.end_sniffing,  # TODO think if client ever has to stop sniffing packets
            timeout=10  # TODO If prn will not be invoked in timeout thread will terminate -> maybe it should never terminate?
        ),
        name="thread_sniffing"
    )

    thread_sniffing.start()
    Client.send_discover()
    # sleep(0.25)
    thread_sniffing.join()

# TODO check when to resend Discover if server does not respond with Offer
# TODO check when to resend Request if server does not respond with Ack
# packet.show()   # Displays all elements of every layer of packet