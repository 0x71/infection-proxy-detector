# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
import argparse

if __name__ == "__main__":

    # To Do: Implement argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-c","--count", help="Number of downloads", type=int, default=1, required=False)
    parser.add_argument("-u","--url", help="Download url", type=str, required=True)
    parser.add_argument("-r","--remove", help="Remove downloaded files", action='store_true')
    args = parser.parse_args()
    
    url = args.url.split('/')
    print url
    for x in range(0, args.count):
        os.system("wget %s -p -nv -nd --no-dns-cache" % args.url)
        
        os.remove(url[-1])
        
    print "\nDone.\n"