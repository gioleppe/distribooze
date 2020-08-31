#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
import argparse


def updatechain(who, slot, flows):
    if(not(who in flows)):
        flows[who] = newchain()

    flows[who][slot] = flows[who][slot] + 1

def newchain():
    c = [0 for x in range(maxlen)]
    return c


def scale(len):
    if (len > 1504):
        len = 1504

    return (int(len / 64))

def printchain(a):
    s = sum(a)
    for x in range(maxlen):
        a[x] = int((a[x]*100)/s)

    print(a)

maxlen = int(1504/32)

parser = argparse.ArgumentParser(description='Plot packet lenght distribution')
parser.add_argument('pcap', metavar='P', nargs="+", help='the pcap to analyze')
parser.add_argument('-f', metavar='F', dest="filter",
                    help='an optional filter in BPF syntax to be applied to the pcap. default = "tcp"',
                    default="tcp")

args = parser.parse_args()

print("Analyzing pcap: ", args.pcap)
print("Using BPF filter: ", args.filter)

caps = sniff(offline=args.pcap, filter=args.filter)

flows = {}

for el in [cap for cap in caps if (IP and TCP) in cap]:
    who = (el[IP].src+":"+str(el[TCP].sport),"to", el[IP].dst+":"+str(el[TCP].dport))
    updatechain(who, scale(len(el[IP])), flows)

for host in flows:
    print("Flow " + str(host))
    printchain(flows[host])

