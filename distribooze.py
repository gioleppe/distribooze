#!/usr/bin/env python3

from sklearn.cluster import DBSCAN
from scapy.all import *
from scapy.layers.inet import IP, TCP
import argparse
import numpy as np
import pickle


def updatechain(who, slot, flows):
    if (not (who in flows)):
        # tuple that says to which cluster it belongs
        flows[who] = (newchain(), -1)

    flows[who][0][slot] = flows[who][0][slot] + 1


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

    #print(a)
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
    dist_list = []

    """for host in flows:
        count += 1
        avg += np.array(flows[host])
        dist_list.append(np.array(flows[host]))"""

    dist_list = [np.array(flows[host][0]) for host in flows]
    print(dist_list)
    labels = {}
    clustering = DBSCAN(eps=10).fit(dist_list)
    print(clustering.labels_)

    cluster_avg = {}

    for host, label in zip(flows, clustering.labels_):
        if label in cluster_avg:
            cluster_avg[label][0] += flows[host][0]
            cluster_avg[label][1] += 1
        else:
            cluster_avg[label] = [np.array(newchain()), 0]
            cluster_avg[label][0] = cluster_avg[label][0] + np.array(flows[host][0])
            cluster_avg[label][1] = 1

    for label in cluster_avg:
        cluster_avg[label][0] = np.divide(cluster_avg[label][0], cluster_avg[label][1])

    print(cluster_avg)

    for host, label in zip(flows, clustering.labels_):
        print(host, label)

    """for distribution, label in sorted(zip(dist_list, clustering.labels_), key=lambda t: t[1]):
            avg_dist = printchain(distribution)
            print(label, avg_dist)
    """

    #avg = np.divide(avg, count)

    #print("average distribution for ", args.pcap)
    #distribution = printchain(avg)



maxlen = int(1504 / 32)

parser = argparse.ArgumentParser(description='Plot packet length distribution comparing'
                                             ' it to its mean cluster distribution average.')
parser.add_argument('pcap', metavar='P', nargs="+", help='the pcap to analyze')
parser.add_argument('-f', metavar='F', dest="filter",
                    help='an optional filter in BPF syntax to be applied to the pcap. default = "tcp"',
                    default="tcp")
parser.add_argument("-n", type=int, dest="numclusters", help="The number of the clusters to be used, default = 2",
                    default=2)

args = parser.parse_args()

calc_dist(args.pcap[0])

