# Net watch

This is a very simple python script that uses

- scapy
- a curses based TUI

to provide a simple tool to analyse the network traffic on a device running linux.

## Why not use tcpdump ?

tcpdump is great but

- it is hard to get the global view from it's fast scrolling output
- it is hard to spot unwanted traffic
- it is such an amazing program

This was scriptted in an attempt to know

- Who are all my noisy neighbours on the network
- Which apps are consuming bandwidth, and who do they talk to
- Where do my packets go

## Features

- Determines the amount of packets sent and recieved per second by ip address
- Listens for all packets
- Determines the process responsible for each communication
- Tries to be efficient (atomic replacement of data to prevent locks) without being CPU intensive (sleeps most of the time)

It needs to run with sudo privileges
