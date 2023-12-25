def get_option_value(option_list, option):
    option_list_filtered = [option for option in option_list if isinstance(option, tuple)]  # Removing "end", "pad" elements
    return next((value for name, value in option_list_filtered if name == option), None)    # Extracting value of option securly, option can be at any place in list of DHCP options
