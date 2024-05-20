#!/bin/bash

if (($EUID > 0)); then
    echo "You have to run this script with root privileges"
    exit
fi

ip link del vt-green-br
ip link del vt-red-br
ip link del vt-blue-br 
ip link del vt-grey-br
ip link del vt-orange-br

ip netns del ns-green
ip netns del ns-blue
ip netns del ns-red
ip netns del ns-grey
ip netns del ns-orange

ip link del vt-br-west

ip link del dev br-east
ip link del dev br-west
