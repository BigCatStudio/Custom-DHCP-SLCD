from scapy.all import sendp, sniff, get_if_raw_hwaddr, conf
from scapy.arch import get_if_addr
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from threading import Thread, Timer
from time import sleep
from sys import argv
from utilities import IP_Pool, get_option_value, mac_to_bytes, bytes_to_mac


class DHCP_Client_Info:
    def __init__(self, mac_address, ip_offered, transaction_id, host_name):
        self.mac_address = mac_address
        self.ip_offered = ip_offered
        self.ip_address = "0.0.0.0"
        self.host_name = host_name
        self.transaction_id = transaction_id
        self.timer_lease = None     # It will measure if lease time passes
        self.activity = True

    def __str__(self):
        return "\nAssociated DHCP client info:" + \
               f"\n\t{self.mac_address}" + \
               f"\n\t{self.ip_address}" + \
               f"\n\t{self.host_name}"


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
                 f"\n\tHost name: {self.host_name}" + \
                 f"\n\tInterface: {self.interface}" + \
                 f"\n\tMAC address (bytes): {self.mac_server}" + \
                 f"\n\tMAC address (string): {bytes_to_mac(self.mac_server)}" + \
                 f"\n\tIP address: {self.ip_server}"
        return output

    def lease_time_passed(self, transaction_id):
        client = self.get_client(transaction_id)
        if client is not None:
            ip_address = client.ip_address
            print(f"Lease time passed for: {ip_address}")
            self.ip_poll.free_ip_address(ip_address)    # Freeing ip address
            self.Clients_Info = [client for client in self.Clients_Info if client.transaction_id != transaction_id]     # Removing Clients info

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
        print(f"\nSent DHCP Offer for IP: {Client_Info.ip_offered}")
        sendp(packet, iface=self.interface, verbose=False)

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
        print(f"\nSent DHCP Ack for IP: {Client_Info.ip_offered}")
        sendp(packet, iface=self.interface, verbose=False)
        Client_Info.ip_address = Client_Info.ip_offered
        if Client_Info.timer_lease is not None:     # Resetting timer of lease time if needed
            Client_Info.timer_lease.cancel()

        Client_Info.timer_lease = Timer(self.lease_time, self.lease_time_passed, args=[Client_Info.transaction_id])
        Client_Info.timer_lease.start()

    def packet_handler(self, packet):
        if DHCP in packet:
            match get_option_value(packet[DHCP].options, "message-type"):
                case 1:  # DHCP Discover
                    ip_offered = next(self.ip_poll)     # Choosing IP address for client
                    if ip_offered is not None:
                        Client_Info = self.get_client(packet[BOOTP].xid)
                        if Client_Info is not None:     # Checking if server already have active session with client
                            Client_Info.ip_offered = ip_offered
                        else:
                            Client_Info = DHCP_Client_Info(packet[Ether].src,
                                                           ip_offered,
                                                           packet[BOOTP].xid,
                                                           get_option_value(packet[DHCP].options, "hostname"))
                            self.Clients_Info.append(Client_Info)
                        print(f"\nReceived DHCP Discover from MAC: {Client_Info.mac_address} Transaction ID: {packet[BOOTP].xid}")
                        self.send_offer(Client_Info)
                case 3:  # DHCP Request
                    Client_Info = self.get_client(packet[BOOTP].xid)
                    if (Client_Info is not None) and (get_option_value(packet[DHCP].options, "server_id") == self.ip_server):    # Checking if server does have active session with client and allocated offered IP address
                        if Client_Info.ip_offered == get_option_value(packet[DHCP].options, "requested_addr"):
                            if Client_Info.timer_lease is not None:     # Resetting timer if client requests address before lease time passes
                                Client_Info.timer_lease.cancel()
                            print(f"\nReceived DHCP Request for: {Client_Info.ip_offered} Transaction ID: {packet[BOOTP].xid}")
                            self.send_ack(Client_Info)


if __name__ == "__main__":
    if len(argv) != 5:
        print("Provide proper amount of arguments")
        exit()

    conf.checkIPaddr = False    # It has to be disabled for scapy to not associate all incoming packets with one IP address

    try:
        Server = DHCP_Server(conf.iface, get_if_raw_hwaddr(conf.iface)[1], get_if_addr(conf.iface), argv[1], argv[2], argv[3], int(argv[4]))
    except ValueError:
        print("Provided addresses or lease time has invalid format")
        exit()

    print(Server)

    thread_sniffing = Thread(
        target=lambda: sniff(
            filter="udp and (port 67 or port 68)",
            prn=Server.packet_handler
        ),
        name="thread_sniffing",
        daemon=True     # Enabling CTRL+C to close whole program without waiting for thread to stop executing
    )

    thread_sniffing.start()

    try:
        while True:
            clients_amount = len(Server.Clients_Info)

            new_list = []
            for client in Server.Clients_Info:
                if (client.ip_address == "0.0.0.0") and (client.activity is False):   # Removing client sessions that are inactive for too long
                    Server.ip_poll.free_ip_address(client.ip_offered)
                else:
                    new_list.append(client)
            Server.Clients_Info = new_list

            if clients_amount > len(Server.Clients_Info):
                print(f"Clients removed because of not continuing DHCP messages exchange: {clients_amount - len(Server.Clients_Info)}")

            for client in Server.Clients_Info:
                if client.ip_address == "0.0.0.0":
                    if client.activity:
                        client.activity = False
                else:
                    client.activity = True
            sleep(10)
    except KeyboardInterrupt:
        print("INTERRUPT FROM KEYBOARD")
