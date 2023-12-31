from scapy.all import sendp, sniff, get_if_raw_hwaddr, conf
from scapy.arch import get_if_addr
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread, Timer
from utilities import IP_Pool, get_option_value, mac_to_bytes, bytes_to_mac


class DHCP_Client_Info:
    def __init__(self, mac_address, ip_offered, transaction_id, host_name):
        self.mac_address = mac_address
        self.ip_offered = ip_offered
        self.ip_address = "0.0.0.0"   # TODO it will be "0.0.0.0" until Ack with IP is send to client
        self.host_name = host_name
        self.transaction_id = transaction_id
        self.timer_lease = None     # It will measure if lease time passes

    def __str__(self):
        return "\nAssociated DHCP client info:" + \
               f"\n\t{self.mac_address}" + \
               f"\n\t{self.ip_address}" + \
               f"\n\t{self.host_name}"

    # def start_timer(self):
    #     self.timer_lease.start()


class DHCP_Server:
    def __init__(self, interface, mac_server, ip_server, ip_pool_start, ip_pool_end, subnet_mask, lease_time):
        self.ip_poll = IP_Pool(ip_pool_start, ip_pool_end, subnet_mask)
        self.Clients_Info = []
        self.host_name = "server-" + str(interface)
        self.interface = interface
        self.mac_server = mac_server
        self.ip_server = ip_server      # Initially interface does not have assigned IP address
        self.lease_time = lease_time
        self.renewal_time = lease_time // 2     # Almost always half of lease_time

    def __str__(self):
        output = "\nServer info:" + \
                 f"\nInterface: {self.interface}" + \
                 f"\nMAC address (bytes): {self.mac_server}" + \
                 f"\nMAC address (string): {bytes_to_mac(self.mac_server)}" + \
                 f"\nIP address: {self.ip_server}"
        return output

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

    # TODO add handling for all DHCP message types
    # 1: DHCPDISCOVER
    # 2: DHCPOFFER
    # 3: DHCPREQUEST
    # 4: DHCPDECLINE
    # 5: DHCPACK
    # 6: DHCPNAK
    # 7: DHCPRELEASE
    # 8: DHCPINFORM

    def get_client(self, transaction_id):
        for client in self.Clients_Info:
            if transaction_id == client.transaction_id:
                return client
        return None

    def send_offer(self, Client_Info):
        packet = Ether(src=self.mac_server, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=self.ip_server, dst="255.255.255.255", ttl=64) / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2,
                       xid=Client_Info.transaction_id,
                       chaddr=mac_to_bytes(Client_Info.mac_address),
                       yiaddr=Client_Info.ip_offered,
                       siaddr=self.ip_server) / \
                 DHCP(options=[("message-type", "offer"),
                               ("hostname", self.host_name),
                               ("server_id", self.ip_server),
                               ("lease_time", self.lease_time),
                               ("renewal_time", self.renewal_time), "end"])
                               # ("param_req_list", [1, 12, 28, 51, 58]), "end"])
        sendp(packet, iface=self.interface)
        print(f"\nSent DHCP Offer for IP: {Client_Info.ip_offered}")

    def send_ack(self, Client_Info):
        packet = Ether(src=self.mac_server, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=self.ip_server, dst="255.255.255.255", ttl=64) / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2,
                       xid=Client_Info.transaction_id,
                       chaddr=mac_to_bytes(Client_Info.mac_address),
                       yiaddr=Client_Info.ip_offered,
                       siaddr=self.ip_server) / \
                 DHCP(options=[("message-type", "ack"),
                               ("hostname", self.host_name),
                               ("server_id", self.ip_server),
                               ("lease_time", self.lease_time),
                               ("renewal_time", self.renewal_time), "end"])
                                # ("param_req_list", [1, 12, 28, 51, 58]), "end"])
        sendp(packet, iface=self.interface)
        print(f"\nSent DHCP Ack for IP: {Client_Info.ip_offered}")
        # print(f"{packet.summary()}")

    def packet_handler(self, packet):
        # TODO Check how server can take IP address from client before lease time
        if DHCP in packet:
            match get_option_value(packet[DHCP].options, "message-type"):
                case 1:  # DHCP Discover
                    Client_Info = self.get_client(packet[BOOTP].xid)
                    if Client_Info is not None:
                        Client_Info.ip_offered = next(self.ip_poll)
                    else:
                        Client_Info = DHCP_Client_Info(packet[Ether].src,
                                                       next(self.ip_poll),  # Choosing IP address for client
                                                       packet[BOOTP].xid,
                                                       get_option_value(packet[DHCP].options, "hostname"))
                        self.Clients_Info.append(Client_Info)
                    print(f"\nReceived DHCP Discover from MAC: {Client_Info.mac_address} Hostaname: {Client_Info.host_name} Transaction ID: {packet[BOOTP].xid}")
                    self.send_offer(Client_Info)
                    # TODO check if addresses and data provided by client are valid to continue exchanging messages
                    # TODO After what time should data about client be deleted, in case client does not get IP Address
                case 3:  # DHCP Request
                    Client_Info = self.get_client(packet[BOOTP].xid)
                    if Client_Info is not None:    # Checking if server does have active session with client and allocated offered IP address
                        if Client_Info.ip_offered == get_option_value(packet[DHCP].options, "requested_addr"):
                            print(f"\nReceived DHCP Request from MAC: {Client_Info.mac_address} Hostaname: {Client_Info.host_name}")
                            self.send_ack(Client_Info)


if __name__ == "__main__":
    conf.checkIPaddr = False    # TODO check if it needs to be set for server
    Server = DHCP_Server(conf.iface, get_if_raw_hwaddr(conf.iface)[1], get_if_addr(conf.iface), "10.10.7.5", "10.10.7.50", "255.255.255.192", 40)

    thread_sniffing = Thread(
        target=lambda: sniff(
            filter="udp and (port 67 or port 68)",   # TODO change to 67 - only for server
            prn=Server.packet_handler,
            timeout=1000  # TODO If prn will not be invoked in timeout thread will terminate -> maybe it should never terminate?
            # TODO if i click CTRL + C should allocated IP address be removed for interface?
            # TODO handle CTRL + C interrupt
        ),
        name="thread_sniffing"
    )

    thread_sniffing.start()
    # sleep(0.25)
    thread_sniffing.join()
