def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options


def mac_to_bytes(mac_address):
    return bytes.fromhex(mac_address.replace(':', ''))  # Remove any delimiters (like ':') from the MAC address and convert it to bytes


def bytes_to_mac(mac_address):
    return ":".join("{:02x}".format(byte) for byte in mac_address)  # Convert bytes back to MAC address format with colon separators
