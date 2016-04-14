# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.

import logging

log = logging.getLogger(__name__)


class TCPStream():
    ''' TCP packet allocation ''' 
    def __init__(self):
        # a tcp stream is identified by source and destination ip + port
        self.src_addr = None
        self.src_port = None
        self.dest_addr = None
        self.dest_port = None
        self.packets = []
        self.first_timestamp = 0 # When was the first packet seen?
        self.packet_count = 0
        self.conn_close = 0 # 1: First (SYN, ACK), 2: Second (SYN,ACK), 3: Final ACK
        self.identifier = None # Unique stream identifier for sniffing session
        self.contains_download = False
        self.file_url = None
        self.file_name = None
        self.file_size = 0
        self.proxy_detected = False

    def __iter__(self):
        return iter(self.packets)

    def __getitem__(self, index):
        return self.packets[index]

    def index(self, packet):
        return self.packets.index(packet)

    def __len__(self):
        return len(self.packets)

    def add_packet(self, packet):
        # add the whole packet to the tcpstream      
        self.packets.append(packet)
        
        # increment total number of packets in stream
        self.packet_count = self.packet_count + 1
        
        # check for the first packet (syn packet)
        if len(self.packets) == 1:
            # log.debug("Syn packet identified.")
            self.src_addr = packet["ip"].src_addr
            self.dest_addr = packet["ip"].dest_addr
            self.src_port = packet["tcp"].src_port
            self.dest_port = packet["tcp"].dest_port
            # log.debug("SRC: %s:%s, DEST: %s:%s", self.src_addr, self.src_port, self.dest_addr, self.dest_port)
            
        # log.debug("TCP DATA segment size: %s", packet["tcp"].get_data_size(packet["ip"].total_length))

    def remove_packet(self,packet):
        # remove the packet
        self.packets.remove(packet)

        # decrement total number of packets in stream
        self.packet_count = self.packet_count - 1

    def is_equal(self, src_addr, dest_addr, src_port, dest_port):
        if self.src_addr == src_addr:
            if self.dest_addr == dest_addr:
                if self.src_port == src_port:
                    if self.dest_port == dest_port:
                        return True    
        elif self.src_addr == dest_addr:
            if self.dest_addr == src_addr:
                if self.src_port == dest_port:
                    if self.dest_port == src_port:
                        return True
        return False

    def sort_packets(self):
        ''' Called to arrange tcp packets comparing their sequence numbers. '''
        self.packets = sorted(self.packets,key=self.get_key)

    def get_key(self, packet):
        ''' Provides the key (sequence number) that is used to arrange the tcp packets. '''
        return packet["tcp"].seq_num