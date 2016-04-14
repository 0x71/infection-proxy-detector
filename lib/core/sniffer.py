# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.

import sys
import logging
from time import time
from socket import *

try:
    from lib.common.colors import color
    from modules.mypacket import MyPacket

except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
log = logging.getLogger()

class Sniffer():
    def __init__(self, sniff_sock=None):
        # To Do: Error Handling
        self.my_socket = sniff_sock
        self.raw_data = None
        self.packet_count = 0
        self.scope_count = 0
        # self.tcp_streams = []
        self.filter = []
        
        # start socket
        self.my_socket.start()
    
    def add_filter(self, protocol):
        if protocol not in self.filter:
            self.filter.append(protocol)
        
    def sniff(self):
        raw_data = self.my_socket.recv()
        t = time()
        #log.debug(data)

        # Count all packets I see
        self.packet_count = self.packet_count + 1 # got one!

        # Create an empty packet
        my_packet = MyPacket()
        my_packet.timestamp = t

        # Extract ethernet frame
        my_packet.add_layer("eth")
        my_packet["eth"].unpack(raw_data) 

        # Check interface before unpacking
        if my_packet["eth"].interface in self.my_socket.interfaces:

            # We are just interested in IP packets for now
            if my_packet["eth"].contains_ip():
                # Extract ip frame
                my_packet.add_layer("ip")
                my_packet["ip"].unpack(my_packet["eth"].data)

                if my_packet["ip"].contains_udp() and "udp" in self.filter: # UDP
                    my_packet.add_layer("udp")
                    my_packet["udp"].unpack(my_packet["ip"].data)

                    if my_packet["udp"].contains_dns() and "dns" in self.filter: # DNS

                        my_packet.add_layer("dns")
                        my_packet["dns"].unpack(my_packet["udp"].data)

                        return my_packet
                    return my_packet

                elif my_packet["ip"].contains_tcp() and "tcp" in self.filter: # TCP
                    my_packet.add_layer("tcp")
                    my_packet["tcp"].unpack(my_packet["ip"].data)

                    return my_packet
        return None