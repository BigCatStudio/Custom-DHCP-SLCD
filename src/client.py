from scapy.all import * 

if __name__ == "__main__":
    target = "www.google.com"
    ip = scapy.all.IP(dst=target)
    for packet in ip:
        print(packet.summary())
