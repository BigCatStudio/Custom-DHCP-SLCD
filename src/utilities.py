from ipaddress import IPv4Network, IPv4Address, AddressValueError, NetmaskValueError


class IP_Pool:
    @staticmethod       # Those functions are static to allow using them in other parts of system (client and server)
    def check_ip(ip_address):
        try:
            IPv4Address(ip_address)    # Raises exception if does not initialize
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
            if IPv4Address(ip_start) <= IPv4Address(ip_end):
                return True
        return False

    def __init__(self, ip_start, ip_end, subnet_mask):
        if IP_Pool.check_ip_pool(ip_start, ip_end) and IP_Pool.check_subnet_mask(subnet_mask):
            self.ip_start = ip_start
            self.ip_end = ip_end
            self.ip_current = IPv4Address(self.ip_start)
            self.subnet_mask = subnet_mask
            self.ip_list = []
        else:
            raise ValueError

    def __iter__(self):
        self.ip_current = IPv4Address(self.ip_start)
        return self

    def __next__(self):     # Iterating over all possible addresses in range and returning to first one if it reaches end
        if len(self.ip_list) == len(self):      # All addresses are alocated
            return None

        while self.ip_current in self.ip_list:
            if self.ip_current == IPv4Address(self.ip_end):
                self.ip_current = IPv4Address(self.ip_start)
            else:
                self.ip_current += 1

        self.ip_list.append(self.ip_current)
        return str(self.ip_current)

    def __len__(self):
        start = int(IPv4Address(self.ip_start))
        end = int(IPv4Address(self.ip_end))
        return end - start + 1

    def free_ip_address(self, ip_address):
        self.ip_list = [address for address in self.ip_list if address != IPv4Address(ip_address)]


def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options


def mac_to_bytes(mac_address):
    return bytes.fromhex(mac_address.replace(':', ''))


def bytes_to_mac(mac_address):
    return ":".join("{:02x}".format(byte) for byte in mac_address)
