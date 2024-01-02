from scapy.all import sendp, sniff, get_if_raw_hwaddr, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread, Timer
from os import system
from time import sleep
from random import randint
from utilities import get_option_value, mac_to_bytes, bytes_to_mac


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
               f"\n\t{self.broadcast_address}"


class DHCP_Client:
    def __init__(self, interface, mac_client):
        self.host_name = "client-" + str(interface)
        self.interface = interface
        self.mac_client = mac_client
        self.ip_client = "0.0.0.0"      # Initially interface does not have assigned IP address
        self.ip_offered = None
        self.lease_time = 0
        self.renewal_time = 0       # Almost always half of lease_time
        self.transaction_id = randint(0, 4294967295)    # Transaction ID field in DHCP header is 32 bit long
        self.timer_lease = None     # It will measure if lease time passes
        self.timer_renewal = None   # It will measure if renewal time passes
        self.Server_Info = None     # Informations regarding DHCP server

    def __str__(self):
        output = "\nClient info:" + \
                 f"\nInterface: {self.interface}" + \
                 f"\nMAC address (bytes): {self.mac_client}" + \
                 f"\nMAC address (string): {bytes_to_mac(self.mac_client)}" + \
                 f"\nIP address: {self.ip_client}"
        return output

    def clear_info(self):
        system(f"ip addr del {self.ip_client}/24 dev {self.interface}")    # TODO replace 24 with subnet mask length
        self.ip_client = "0.0.0.0"
        self.ip_offered = None
        self.lease_time = 0
        self.renewal_time = 0
        self.timer_lease = None
        self.timer_renewal = None
        self.Server_Info = None

    def renewal_time_passed(self, ip_server):
        print(f"\nRenewal time passed for IP address: {self.ip_client}")
        self.send_request(ip_server)

    def lease_time_passed(self):
        print(f"\nLease time passed for IP address: {self.ip_client}")
        self.clear_info()
        # TODO invoke DHCP Discover (DHCP server might have freed cient's IP address)

    def send_discover(self):
        # TODO should be invoked if client does not have allocated IP address -> maybe timer from the last DHCP Discover:
        # set timer for 10 seconds after every DHCP Discover, if client does not have ip address clear info and send new DHCP discover
        # TODO add xid field generator to BOOTP - how to make unique id for all clients?
        # TODO how to use type=0x800 in Ethernet to allow usage of this program in VLAN 
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255", ttl=64) / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=self.mac_client, xid=self.transaction_id) / \
                 DHCP(options=[("message-type", "discover"),
                               ("hostname", self.host_name),
                               ("param_req_list", [1, 12, 28, 51, 58]), "end"])
        print("\nSent DHCP Discover")
        sendp(packet, iface=self.interface)
        # TODO make availabilty to define TTl for user when creating client -> make that for all options
        # maybe use json file for initial parameters for dhcp client and server like: { ip: [ttl:64] }
        # TODO create json with default DHCP configuration for Client and Server
        # TODO Client and Server should take values from json files when started

    def send_request(self, ip_server):
        packet = Ether(src=self.mac_client, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src="0.0.0.0", dst="255.255.255.255", ttl=64) / \
                 UDP(sport=68, dport=67) / \
                 BOOTP(chaddr=self.mac_client, xid=self.transaction_id) / \
                 DHCP(options=[("message-type", "request"),
                               ("hostname", self.host_name),
                               ("requested_addr", self.ip_offered),
                               ("server_id", ip_server),    # TODO think if it is needed
                               ("param_req_list", [1, 12, 28, 51, 58]), "end"])
        print(f"\nSent DHCP Request for IP: {self.ip_offered} to {ip_server}")
        sendp(packet, iface=self.interface)
        # TODO identyfing client and server should be done based on hostname and ip
        # server -> (hostname, server_id)
        # client -> (hostname, client_id)
        # client should contain information about session with every server and identify messages with it like defined in upper lines
        # same for server (it will exchange messages with many clients)

    def packet_handler(self, packet):
        # TODO Check how server can take IP address from client before lease time
        if (DHCP in packet) and (UDP in packet):
            if (packet[UDP].sport == 67) and (packet[UDP].dport == 68) and (packet[BOOTP].xid == self.transaction_id):  # filter DHCP messages that are related to this client
                match get_option_value(packet[DHCP].options, "message-type"):
                    case 2:  # DHCP Offer
                        # TODO check if offered IP is valid -> regex
                        if self.ip_offered is None:     # Another server might have already sent offered ip_address
                            # TODO change all info below to take info proper layer -> IP addresses from packet[IP]
                            ip_server = packet["BOOTP"].siaddr
                            self.ip_offered = packet[BOOTP].yiaddr
                            self.Server_Info = DHCP_Server_Info(packet[Ether].src,
                                                                packet[IP].src,
                                                                get_option_value(packet[DHCP].options, "hostname"),
                                                                get_option_value(packet[DHCP].options, "subnet_mask"),
                                                                get_option_value(packet[DHCP].options, "broadcast_address"))
                            print(f"\nReceived DHCP Offer for IP address: {self.ip_offered} from {ip_server}")
                            self.send_request(ip_server)
                    case 5:  # DHCP ACK
                        # TODO checking if ACK is received from server that you have info from DHCP Offer
                        if self.ip_offered == packet[BOOTP].yiaddr:
                            print(f"\nReceived DHCP ACK for IP address: {self.ip_offered}")
                            system(f"ifconfig {self.interface} {self.ip_offered}/24")   # TODO instead of 24 -> subnet mask length

                            if self.timer_lease is not None:
                                self.timer_lease.cancel()

                            self.ip_client = self.ip_offered
                            self.lease_time = get_option_value(packet[DHCP].options, "lease_time")
                            self.renewal_time = get_option_value(packet[DHCP].options, "renewal_time")
                            self.timer_lease = Timer(self.lease_time, self.lease_time_passed)
                            self.timer_renewal = Timer(self.renewal_time, self.renewal_time_passed, args=[packet[IP].src])
                            self.timer_lease.start()
                            self.timer_renewal.start()


if __name__ == "__main__":
    conf.checkIPaddr = False    # Has to be set for Discover because scapy sends response by matching IP (255.255.255.255 will never match DHCP server address)
    Client = DHCP_Client(conf.iface, get_if_raw_hwaddr(conf.iface)[1])

    thread_sniffing = Thread(
        target=lambda: sniff(
            # filter="udp and (port 67 or port 68)",   # TODO It is not working for some reason
            prn=Client.packet_handler,
            timeout=1000  # TODO If prn will not be invoked in timeout thread will terminate -> maybe it should never terminate?
            # TODO if i click CTRL + C should allocated IP address be removed for interface?
            # TODO handle CTRL + C interrupt
        ),
        name="thread_sniffing",
        daemon=True
    )

    thread_sniffing.start()

    try:
        while True:
            if Client.ip_client == "0.0.0.0":
                Client.send_discover()
                sleep(10)
    except KeyboardInterrupt:
        if Client.ip_client != "0.0.0.0":
            Client.clear_info()
        print("---------------------- INTERRUPT FROM KEYBOARD -------------------------")

    # thread_sniffing.join()

# TODO check when to resend Discover if server does not respond with Offer
# TODO check when to resend Request if server does not respond with Ack
# packet.show()   # Displays all elements of every layer of packet
