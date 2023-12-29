import ipaddress

class IP_Pool:
    def __init__(self, ip_start, ip_end, subnet_mask):
        self.ip_start = ip_start
        self.ip_end = ip_end
        self.subnet_mask = subnet_mask
        # TODO check if Ip addresses and mask makes sense

    @staticmethod
    def check_ip(ip_address):
        try:
            ip_object = ipaddress.ip_address(ip_address)    # Raises exception if does not initialize
            # TODO check if it is not broadcast or network address
            # print(f"Ip address is valid: {ip_address}")
        except ValueError:
            print(f"Ip address is not valid: {ip_address}")

    @staticmethod
    def check_ip_pool(ip_start, ip_end, subnet_mask):
        if IP_Pool.check_ip(ip_start) and IP_Pool.check_ip(ip_end):
            if ip_start < ip_end:
                print("IP pool good")


def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options


def mac_to_bytes(mac_address):
    return bytes.fromhex(mac_address.replace(':', ''))  # Remove any delimiters (like ':') from the MAC address and convert it to bytes


def bytes_to_mac(mac_address):
    return ":".join("{:02x}".format(byte) for byte in mac_address)  # Convert bytes back to MAC address format with colon separators
