# Custom-DHCP-SLCD

This project allows to create custom DHCP client and server. You can set IP address / network namespace and interface on which DHCP components can run.

This implementation includes:
- DHCPDISCOVER
- DHCPOFFER
- DHCPREQUEST
- DHCPACK

To run client:
python3 ./src/client.py

To run server:
python3 ./src/server.py <IP_poll_start> <IP_poll_end> <subnet_mask> <lease_time>

Requires python 3.10/3.11. Scapy is not currently compatible with newer versions of python
