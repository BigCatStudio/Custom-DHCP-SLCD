from scapy.all import sendp, sniff, get_if_raw_hwaddr, get_if_hwaddr, conf
from scapy.arch import get_if_addr
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread, Timer
from os import system

from utilities import get_option_value


class DHCP_Client_Info:
    def __init__(self, mac_address, ip_address, host_name):
        self.mac_address = mac_address
        self.ip_address = ip_address    # TODO it will be "0.0.0.0" until Ack with IP is send to client
        self.host_name = host_name

    def __str__(self):
        return "\nAssociated DHCP server info:" + \
               f"\n\t{self.mac_address}" + \
               f"\n\t{self.ip_address}" + \
               f"\n\t{self.host_name}"


class DHCP_Server:
    def __init__(self, interface, mac_server, ip_server, ip_pool_start, ip_pool_end, lease_time):
        self.host_name = "server-" + str(interface)
        self.interface = interface
        self.mac_server = mac_server
        self.ip_server = ip_server      # Initially interface does not have assigned IP address
        # TODO create class for handling ip addresses pool
        self.lease_time = lease_time
        self.renewal_time = lease_time // 2     # Almost always half of lease_time
        self.timer_lease = None     # It will measure if lease time passes
        self.timer_renewal = None   # It will measure if renewal time passes
        self.Client_Info = None     # Informations regarding DHCP client

    # def clear_info(self):
    #     self.ip_client = "0.0.0.0"
    #     self.ip_offered = None
    #     self.lease_time = 0
    #     self.renewal_time = 0
    #     self.timer_lease = None
    #     self.timer_renewal = None
    #     self.Server_Info = None

    # def renewal_time_passed(self):
    #     print(f"Renewal time passed for IP address: {self.ip_client}")
    #     # TODO invoke DHCP Request for the same IP address

    # def lease_time_passed(self):
    #     print(f"Lease time passed for IP address: {self.ip_client}")
    #     system(f"ip addr del {self.ip_client}/24 dev {self.interface}")    # TODO replace 24 with subnet mask length
    #     # TODO invoke DHCP Discover (DHCP server might have freed cient's IP address)
    #     self.clear_info()   # TODO what with active timers, should they be stopped?
    #     self.send_discover()    # TODO think, maybe regular discover check should invoke new DHCP Discover

    # TODO check ports for offer
    def send_offer(self):
        packet = Ether(src=self.mac_server, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=self.ip_server, dst="255.255.255.255", ttl=64) / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, chaddr=self.Client_Info.mac_address, yiaddr="10.10.7.20", siaddr=self.ip_server) / \
                 DHCP(options=[("message-type", "offer"),
                               ("hostname", self.host_name),
                               ("server_id", self.ip_server), "end"])
                               # ("requested_addr", "10.10.7.20"), "end"])
                                # TODO add offered IP
                                # ("param_req_list", [1, 12, 28, 51, 58]), "end"])
        sendp(packet, iface=self.interface)
        print("Sent DHCP Offer for IP: 10.10.7.20")
        # print(f"{packet.summary()}")
 
    # TODO check ports for ack
    def send_ack(self, ip_server):
        packet = Ether(src=self.mac_server, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=self.ip_server, dst="255.255.255.255", ttl=64) / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, chaddr=self.Client_Info.mac_address) / \
                 DHCP(options=[("message-type", "ack"),
                               ("hostname", self.host_name), "end"])
                                # ("requested_addr", self.ip_offered),
                                # ("server_id", ip_server),   # TODO think if it is needed
                                # ("param_req_list", [1, 12, 28, 51, 58]), "end"])
        sendp(packet, iface=self.interface)
        print("Sent DHCP Ack for IP: 10.10.7.20")
        # print(f"{packet.summary()}")

    # TODO add handling for all DHCP message types
    # 1: DHCPDISCOVER
    # 2: DHCPOFFER
    # 3: DHCPREQUEST
    # 4: DHCPDECLINE
    # 5: DHCPACK
    # 6: DHCPNAK
    # 7: DHCPRELEASE
    # 8: DHCPINFORM

    def packet_handler(self, packet):
        # TODO Check how server can take IP address from client before lease time
        if DHCP in packet:
            match get_option_value(packet[DHCP].options, "message-type"):
                case 1:  # DHCP Discover
                    self.Client_Info = DHCP_Client_Info(packet[Ether].src,
                                                        packet[IP].src,
                                                        get_option_value(packet[DHCP].options, "hostname"))
                    print(f"Received DHCP Discover from MAC: {self.Client_Info.mac_address} Hostaname: {self.Client_Info.host_name} IP: {self.Client_Info.ip_address}")
                    self.send_offer()
                    # TODO check if addresses and data provided by client are valid to continue exchanging messages
                    
                    # TODO extracting DHCP client info and saving new session with client -> (maybe create some structure to keep all active sessions with clients)
                    # After what time should data about client be deleted, in case client does not get IP Address
                case 3:  # DHCP Request
                    print("Managing DHCP Request")
            # print(f"{packet.summary()}")

    # def end_sniffing():
    #     print("Server is not sniffing")

    def __str__(self):
        output = "\nServer info:" + \
                 f"\nInterface: {self.interface}" + \
                 f"\nMAC address (bytes): {self.mac_server}" + \
                 f"\nMAC address (string): {get_if_hwaddr(conf.iface)}" + \
                 f"\nIP address: {self.ip_server}"
        return output


if __name__ == "__main__":
    conf.checkIPaddr = False    # TODO check if it needs to be set for server
    Server = DHCP_Server(conf.iface, get_if_raw_hwaddr(conf.iface)[1], get_if_addr(conf.iface), "10.10.7.5", "10.10.7.50", 3600)

    thread_sniffing = Thread(
        target=lambda: sniff(
            filter="udp and ( port 67 or port 68 )",   # TODO change to 67 - only for server
            prn=Server.packet_handler,
            # stop_filter=Server.end_sniffing,  # TODO think if client ever has to stop sniffing packets
            timeout=1000  # TODO If prn will not be invoked in timeout thread will terminate -> maybe it should never terminate?
            # TODO if i click CTRL + C should allocated IP address be removed for interface?
            # TODO handle CTRL + C interrupt
        ),
        name="thread_sniffing"
    )

    thread_sniffing.start()
    # sleep(0.25)
    thread_sniffing.join()
