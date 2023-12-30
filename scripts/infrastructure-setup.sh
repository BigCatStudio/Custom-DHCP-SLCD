#!/bin/bash

if (($EUID > 0)); then
    echo "You have to run this script with root privileges"
    exit
fi

sysctl -w net.bridge.bridge-nf-call-arptables=0
sysctl -w net.bridge.bridge-nf-call-iptables=0


# Green namespace
ip netns add ns-green
ip netns exec ns-green ip link set dev lo up
ip link add vt-green type veth peer name vt-green-br
ip link set vt-green netns ns-green
ip netns exec ns-green ip addr add 10.10.7.1/24 dev vt-green
ip netns exec ns-green ip link set vt-green up


# Blue namespace
ip netns add ns-blue
ip netns exec ns-blue ip link set dev lo up
ip link add vt-blue type veth peer name vt-blue-br
ip link set vt-blue netns ns-blue
# ip netns exec ns-blue ip addr add 10.10.7.2/24 dev vt-blue
ip netns exec ns-blue ip link set vt-blue up


# Red namespace
ip netns add ns-red
ip netns exec ns-red ip link set dev lo up
ip link add vt-red type veth peer name vt-red-br
ip link set vt-red netns ns-red
ip netns exec ns-red ip addr add 10.10.8.1/24 dev vt-red
ip netns exec ns-red ip link set vt-red up


# Grey namespace
ip netns add ns-grey
ip netns exec ns-grey ip link set dev lo up

ip link add vt-grey1 type veth peer name vt-grey1-br
ip link set vt-grey1 netns ns-grey
ip netns exec ns-grey ip addr add 10.10.7.3/24 dev vt-grey1
ip netns exec ns-grey ip link set vt-grey1 up

ip link add vt-grey2 type veth peer name vt-grey2-br
ip link set vt-grey2 netns ns-grey
ip netns exec ns-grey ip addr add 10.10.8.2/24 dev vt-grey2
ip netns exec ns-grey ip link set vt-grey2 up


# Bridge east
ip link add br-east type bridge
ip link set dev br-east up

ip link set vt-green-br master br-east
ip link set dev vt-green-br up

ip link set vt-blue-br master br-east
ip link set dev vt-blue-br up

ip link set vt-red-br master br-east
ip link set dev vt-red-br up


# Bridge west
ip link add br-west type bridge
ip link set dev br-west up

ip link set vt-grey1-br master br-west
ip link set dev vt-grey1-br up

ip link set vt-grey2-br master br-west
ip link set dev vt-grey2-br up


# Linking bridges
ip link add vt-br-east type veth peer name vt-br-west
ip link set vt-br-west master br-east
ip link set vt-br-west up
ip link set vt-br-east master br-west
ip link set vt-br-east up


# Possibility to test reachability by providing additional argument -> "test"
if [ $# -ge 1 ] && [ "$1" = "test" ]; then
    ip netns exec ns-green ping 10.10.7.2 -c 4
    ip netns exec ns-red ping 10.10.8.2 -c 4
    ip netns exec ns-grey ping 10.10.7.1 -c 4
    ip netns exec ns-grey ping 10.10.8.1 -c 4
fi  


# Displaying terminals for each namespace
ip netns exec ns-green xterm -xrm 'XTerm.vt100.allowTitleOps: false' -title 'green: 10.10.7.1' -fa 'Monospace' -fs 12 -bg darkgreen -e 'cd ../src && /bin/bash' &
ip netns exec ns-blue xterm -xrm 'XTerm.vt100.allowTitleOps: false' -title 'blue: ' -fa 'Monospace' -fs 12 -bg darkblue -e 'cd ../src && /bin/bash' &


# Testing purpouses commands
# sudo ip netns exec ns-green dnsmasq --dhcp-range=10.10.7.20,10.10.7.25,255.255.255.0,2m --interface=vt-green --no-daemon
# sudo ip netns exec ns-blue dhclient -d vt-blue
