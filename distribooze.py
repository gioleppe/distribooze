#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
import argparse

maxlen = int(1504/32)

parser = argparse.ArgumentParser(description='Plot packet lenght distribution')
parser.add_argument('pcap', metavar='P', nargs="+", help='the pcap to analyze')
parser.add_argument('-f', metavar='F', dest="filter",
                    help='an optional filter in BPF syntax to be applied to the pcap. default = "tcp"',
                    default="tcp")