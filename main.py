#!/usr/bin/env python

import scapy.all as scapy
import argparse


def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")
    options = parser.parse_args()
    return options


def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast / arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

    clientList = []
    for element in answeredList:
        clientDict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clientList.append(clientDict)
    return clientList


def printResult(result):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in result:
        print(client["ip"] + "\t\t" + client["mac"])


options = getArguments()
scanResult = scan(options.target)
printResult(scanResult)