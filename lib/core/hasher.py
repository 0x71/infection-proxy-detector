# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.
import logging
import Queue
from threading import Thread, Event
import httplib, urllib
import syslog
import sys
import os
import ConfigParser

try:
    from lib.common.colors import color
    from lib.common.constants import ETHERSNIFF_ROOT
except ImportError as e:
    sys.exit("ERROR: Missing library: {0}".format(e))

log = logging.getLogger()

class Hasher(Thread):
    
    stoprequest = Event()
    
    def __init__(self):
        Thread.__init__(self) # init thread class
        log.debug("Hasher started.")
        self.q = Queue.Queue() # Queue to hold all crude packets
        self.servers = []
        self.active = True

        self.read_config()

    def __del__(self):
        log.debug("Hasher destroyed.")
        
    def read_config(self):
        cfg = ConfigParser.ConfigParser()

        try:
            cfg.read(os.path.join(ETHERSNIFF_ROOT, "conf", "hasher.conf"))
            servers = cfg.get("hasher","servers")
            if len(servers) == 0:
                log.info("No servers for remote check in config file. Hasher module disabled.")
                self.active = False
            else:
                for server in servers.split(','):
                    tmp = dict()
                    tmp["label"] = cfg.get(server,"label")
                    tmp["address"] = cfg.get(server,"address")
                    tmp["path"] = cfg.get(server,"path")
                    tmp["type"] = cfg.get(server,"type")
                    tmp["user"] = cfg.get(server,"user")
                    tmp["password"] = cfg.get(server,"password")
                    self.servers.append(tmp)
                    log.debug("  |--- Remote server '" + self.servers[-1]["label"] + "' added.")
        except:
            sys.exit(sys.exit("ERROR: Reading 'hasher.conf'"))

    def add_file_check(self, url, hash_val):
        self.q.put([url,hash_val])
        
    def run(self):
        while not Hasher.stoprequest.is_set():
            try:
                url, hash_val = self.q.get(block=True, timeout=0.5)
                remote_hashes = []
                for server in self.servers:
                    if url and hash_val:
                        if ".exe" in url or ".zip" in url or "tar.gz" in url:
                            log.debug("Requesting remote check ('%s')", server["label"])
                            params = urllib.urlencode({'user': server["user"], 'p': server["password"], 'url': url})
                            headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}
                            conn = httplib.HTTPSConnection(server["address"])
                            conn.request(server["type"], server["path"], params, headers)
                            response = conn.getresponse()
                            # print response.status, response.reason

                            data = response.read()
                            conn.close()

                            if "invalid" in data:
                                log.error("Could not obtain remote hash.")
                            else:
                                remote_hashes.append(data.split()[0])

                # Compare hash values
                log.info("Remote hashes:")
                count = 0
                for val in remote_hashes:
                    log.info("  |--- %s", val)
                    if hash_val in val:
                        pass
                        # log.info("File is not infected.")
                    else:
                        count = count + 1

                if count == 0:
                    log.debug("File is not infected.")
                else:
                    log.critical(color("File is most probably infected. Hash sum mismatch (%d/%d) & proxy detected!",1),count,len(remote_hashes))
                    syslog.syslog(syslog.LOG_CRIT, "File is most probably infected. Hash sum mismatch & proxy detected!")

            except Queue.Empty:
                continue

