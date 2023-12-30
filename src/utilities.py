from ipaddress import IPv4Network, IPv4Address, AddressValueError, NetmaskValueError


class IP_Pool:
    @staticmethod
    def check_ip(ip_address):
        try:
            # TODO check if it is not broadcast or network address
            # print(f"Ip address is valid: {ip_address}")
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
            self.subnet_mask = subnet_mask
            print("True")
        else:
            print("False")
            # TODO should raise exception

    def __iter__(self):
        self.ip_current = IPv4Address(self.ip_start)
        return self

    def __next__(self):
        if self.ip_current <= IPv4Address(self.ip_end):
            x = self.ip_current
            self.ip_current += 1
            return str(x)
        raise StopIteration
        # TODO add checking if address is available -> in server there will be list of all clients: x will store number of all ip addresses if next(IP_Pool) will not be available for x times poll is empty

    def __len__(self):
        start = int(IPv4Address(self.ip_start))
        end = int(IPv4Address(self.ip_end))
        return end - start + 1


def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options


def mac_to_bytes(mac_address):
    return bytes.fromhex(mac_address.replace(':', ''))  # Remove any delimiters (like ':') from the MAC address and convert it to bytes


def bytes_to_mac(mac_address):
    return ":".join("{:02x}".format(byte) for byte in mac_address)  # Convert bytes back to MAC address format with colon separators


if __name__ == "__main__":
    # TODO move to test directory
    # if IP_Pool.check_subnet_mask("255.255.255.0"):
    #     print("1")
    # if IP_Pool.check_subnet_mask("255.168.255.0"):
    #     print("2")
    # if IP_Pool.check_subnet_mask("255.300.255.0"):
    #     print("3")
    # if IP_Pool.check_ip_pool("192.168.0.3", "192.168.0.10"):
    #     print("4")
    # if IP_Pool.check_ip_pool("000", "1.1.1.1"):
    #     print("5")
    poll = IP_Pool("10.10.10.1", "10.10.11.10", "255.255.255.240")
    i = 1
    for x in poll:
        print(f"{i}: {x}")
        i += 1
    print(f"Length of poll: {len(poll)}")
