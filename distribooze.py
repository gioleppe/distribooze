#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, TCP
import argparse
import numpy as np
import pickle


def updatechain(who, slot, flows):
    if (not (who in flows)):
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
        a[x] = int((a[x] * 100) / s)

    print(a)
    return a


def calc_dist(pcap):
    print("Analyzing pcap: ", args.pcap)
    print("Using BPF filter: ", args.filter)

    caps = sniff(offline=args.pcap, filter=args.filter)

    flows = {}

    for el in [cap for cap in caps if (IP and TCP) in cap]:
        who = (el[IP].src + ":" + str(el[TCP].sport), "to", el[IP].dst + ":" + str(el[TCP].dport))
        updatechain(who, scale(len(el[IP])), flows)

    """for host in flows:
        print("Flow " + str(host))
        printchain(flows[host])"""

    avg = np.array(newchain())
    count = 0

    for host in flows:
        count += 1
        avg += np.array(flows[host])

    avg = np.divide(avg, count)

    print("average distribution for ", args.pcap)
    distribution = printchain(avg)

    print("updating distribution dictionary with ", args.pcap)

    pick = {}

    try:
        pick = pickle.load(open("dists.p", "rb"))
        pick[args.pcap[0]] = distribution
        # print(pick)
    except (OSError, IOError) as e:
        print("dictionary doesn't exist yet, creating it now.")
        pick[args.pcap[0]] = distribution

    pickle.dump(pick, open("dists.p", "wb"))
    return distribution


maxlen = int(1504 / 32)

parser = argparse.ArgumentParser(description='Plot packet lenght distribution')
parser.add_argument('pcap', metavar='P', nargs="+", help='the pcap to analyze')
parser.add_argument('-f', metavar='F', dest="filter",
                    help='an optional filter in BPF syntax to be applied to the pcap. default = "tcp"',
                    default="tcp")
parser.add_argument('-c', dest="comp",
                    help='compares the pcap distribution to previously computed ones',
                    action="store_true")

args = parser.parse_args()

if args.comp:
    print("Comparing " + str(args.pcap) + " to previously computed distributions")
    try:
        dists = pickle.load(open("dists.p", "rb"))
    except (OSError, IOError) as e:
        print("There's no dictionary saved for previous distributions!")
        exit(0)

    #print(dists)

    if args.pcap[0] in dists:
        print("Distribution already present in the dictionary, recovering it from there")
        dist = dists[args.pcap[0]]
    else:
        dist = calc_dist(args.pcap[0])

    results = {}

    for cap in dists:
        results[cap] = np.linalg.norm(dist - dists[cap])
        #print(np.linalg.norm(dist - dists[cap]))

    for elem in sorted(results, key=results.get):
        print("Similarity to " + elem + " : " + str(np.exp(-results[elem])))
        if results[elem] == 0:
            print("The two vectors are identical! This is probably the same pcap")

else:
    calc_dist(args.pcap[0])
