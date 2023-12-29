from ipaddress import IPv4Network, ip_address, AddressValueError, NetmaskValueError


class IP_Pool:
    def __init__(self, ip_start, ip_end, subnet_mask):
        self.ip_start = ip_start
        self.ip_end = ip_end
        self.subnet_mask = subnet_mask
        # TODO upper variables are not probably needed

    def get_ip_address(self):
        return self.ip_start

    @staticmethod
    def check_ip(ip_address):
        try:
            # TODO check if it is not broadcast or network address
            # print(f"Ip address is valid: {ip_address}")
            IPv4Network(ip_address)    # Raises exception if does not initialize
            return True
        except AddressValueError:
            return False

    @staticmethod
    def check_subnet_mask(subnet_mask):
        try:
            IPv4Network(f"0.0.0.0/{subnet_mask}")
            return True
        except (AddressValueError, NetmaskValueError):
            return False

    @staticmethod
    def check_ip_pool(ip_start, ip_end):
        if IP_Pool.check_ip(ip_start) and IP_Pool.check_ip(ip_end):
            if ip_address(ip_start) < ip_address(ip_end):
                return True
        return False


def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options


def mac_to_bytes(mac_address):
    return bytes.fromhex(mac_address.replace(':', ''))  # Remove any delimiters (like ':') from the MAC address and convert it to bytes


def bytes_to_mac(mac_address):
    return ":".join("{:02x}".format(byte) for byte in mac_address)  # Convert bytes back to MAC address format with colon separators


if __name__ == "__main__":
    # TODO move to test directory
    if IP_Pool.check_subnet_mask("255.255.255.0"):
        print("1")
    if IP_Pool.check_subnet_mask("255.168.255.0"):
        print("2")
    if IP_Pool.check_subnet_mask("255.300.255.0"):
        print("3")
    if IP_Pool.check_ip_pool("192.168.0.3", "192.168.0.10"):
        print("4")
    if IP_Pool.check_ip_pool("000", "1.1.1.1"):
        print("5")
