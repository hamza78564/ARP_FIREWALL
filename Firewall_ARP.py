#!/usr/bin/env python3 
from scapy.all import *
import signal

class ArpDetector:
    def __init__(self):
        self.router_ip =conf.route.route("0.0.0.0")[2]
        self.real_router_mac= getmacbyip(self.router_ip)
        print('Start detecting ...')
    def scanerr(self,pkt):
        if pkt.haslayer(ARP):
            if pkt[ARP].psrc == self.router_ip:
                router_mac =pkt[ARP].hwsrc
                if router_mac.lower() != self.real_router_mac.lower():
                    print(f"[!] Warnning : ARP Spoofing Detected! Attacker Mac : {router_mac} ")

detector = ArpDetector()
sniff(
    iface="eth0",filter='arp',prn=detector.scanerr,store=0
)