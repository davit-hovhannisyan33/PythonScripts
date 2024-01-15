#!/usr/bin/env python

import scapy.all as scapy
import argparse
def get_arguments():
    # Parser for options
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="IP Range that you want to scan")
    arguments = parser.parse_args()
    if not arguments.ip:
        parser.error("[-] Please specify an target, use --help for more info. ")
    return arguments
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
def print_result(clients_list):
    for client in clients_list:
        client_check= client["ip"]+ "\t\t" + client["mac"]
        print(client_check)

arguments = get_arguments()
scan_result = scan(arguments.ip)
if not scan_result:
    print("[-] Something went wrong. Please specify a valid target IP range, e.g., 10.0.2.1/24")
else:
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    print_result(scan_result)