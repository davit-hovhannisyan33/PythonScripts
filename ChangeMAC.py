#!/usr/bin/env python

import subprocess
import optparse
import time
import re
import base64
def get_arguments():
    # Parser for options
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="mac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info. ")
    elif not options.mac:
        parser.error("[-] Please specify a new mac address, use --help for more info. ")
    return options
def change_mac(interface, mac):
    print("[+] Changing MAC address for " + interface + " to " + mac)
    time.sleep(3)
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", mac])
    subprocess.call(["sudo", "ifconfig", interface, "up"])

def get_current_mac(interface, mac):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    ifconfig_result = ifconfig_result.decode('utf-8')
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    get_base64_mac = base64.b64encode(mac.encode('utf-8'))
    get_base64_mac_search = base64.b64encode(mac_address_search_result.group(0).encode('utf-8'))
    if not mac_address_search_result:
        print("[-] Could not read MAC address")
    if get_base64_mac == get_base64_mac_search:
        print("[+] Your MAC address has been successfully changed" )
    else:
        print("[-] Something went wrong ")

time.sleep(1)
options = get_arguments()
change_mac(options.interface, options.mac)
time.sleep(2)
get_current_mac(options.interface,options.mac)

