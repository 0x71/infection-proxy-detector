# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import argparse
import logging
import signal

try:
    from lib.common.constants import SUPPORTED_PROTOCOLS, ETHERSNIFF_ROOT
    from lib.core.startup import init_logging, interrupt_handler, check_configs
    from lib.core.sniffer import Sniffer
    from lib.core.analyzer import Analyzer
    from modules.rawsocket import RawSocket

except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))
    
signal.signal(signal.SIGINT, interrupt_handler)
log = logging.getLogger()

sniff_interfaces = ["eth0"] # default interface

if __name__ == "__main__":
    
    # To Do: Implement argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-i","--interfaces", help="Filter traffic for a specific interface", type=str, required=False)
    parser.add_argument("-p","--protocols", help="Protocols to be sniffed", type=str, required=False)
    parser.add_argument("-P","--plot", help="Plot file downloads", action="store_true", required=False)
    parser.add_argument("-c","--comment", help="Comment for statistical analysis", type=str, required=False)
    parser.add_argument("-e","--extract", help="Extract suspicious files for later analysis", action="store_true", required=False)
    args = parser.parse_args()
    
    # Start console and file logging
    init_logging()

    # Check for existing config files
    check_configs()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.interfaces:
        sniff_interfaces = args.interfaces.split(",")
        log.debug("Interfaces: %s", repr(sniff_interfaces))

    if args.plot:
        folder_path = os.path.join(ETHERSNIFF_ROOT,"log")
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

    if args.extract:
        folder_path = os.path.join(ETHERSNIFF_ROOT,"dl")
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

    # Init raw socket
    my_socket = RawSocket(sniff_interfaces)
    
    # Init sniffer
    sniff = Sniffer(my_socket)
    if args.protocols:
        filter_list = args.protocols.split(",")
        for protocol in filter_list:
            sniff.add_filter(protocol)
    else:
        for protocol in SUPPORTED_PROTOCOLS:
            sniff.add_filter(protocol)

    # Init analyzer
    analyze = Analyzer(args.plot, args.comment, args.extract)
    analyze.start()

    # Wait for packets
    while True:
        # Receive packets according to filter rules
        my_packet = sniff.sniff()
        if my_packet:
            # Analyze packets
            analyze.add_packet(my_packet)
