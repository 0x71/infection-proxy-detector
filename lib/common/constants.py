# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.

from os import getcwd

ETHERSNIFF_ROOT = getcwd()

SUPPORTED_PROTOCOLS = ["tcp", "udp", "dns"]

IP_HEADER_PROTOCOLS = { "1": "ICMP",
                        "2": "IGMP",
                        "3": "GGP",
                        "4": "IPv4", # IP encapsulation
                        "6": "TCP",
                       "17": "UDP",
                       "27": "RDP",}

# Count packets that were received within the first 90% of the full download time
STREAM_TIMING_THRESHOLD = 0.9

# If the number of packets received within 90% of the full download time is below 10% of all counted packets,
# there seems to be a proxy between us and the download server
STREAM_PACKET_THRESHOLD = 0.1