# Copyright (C) 2015-2016  Nils Rogmann.
# This file is part of infection-proxy detector.
# See the file 'docs/LICENSE' for copying permission.

import logging
import logging.handlers

import os
import sys
from lib.core.analyzer import Analyzer
from lib.core.hasher import Hasher
from lib.common.constants import ETHERSNIFF_ROOT
from lib.common.colors import color

log = logging.getLogger()

def interrupt_handler(signal,frame):
    log.info("Fetched Ctrl+C. Shutting down.")
    Analyzer.stoprequest.set() # Stop analyzer thread
    Hasher.stoprequest.set()
    exit(0)

def init_logging():
    """ Initializes logging. """
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    
    # File logging
    file_handler = logging.handlers.WatchedFileHandler(os.path.join(ETHERSNIFF_ROOT, "ethersniff.log"))
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    
    # Console logging
    console_handler = ConsoleHandler()
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    
    #log_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    #log_handler.setLevel(logging.ERROR)
    #log.addHandler(log_handler)

    # Log level
    log.setLevel(logging.INFO)
    
def check_configs():
    """ Check for existing configs. """

    configs = ("sniffer.conf", "hasher.conf", )
    
    for file in [os.path.join(ETHERSNIFF_ROOT,"conf", fname) for fname in list(configs)]:
        if not os.path.exists(file):
            sys.exit("ERROR: Missing config file: {0}".format(file))
    
class ConsoleHandler(logging.StreamHandler):
    """ Logging to console. """

    def emit(self, record):
        """ Rewrite each record before it is printed to the console. """
        formatted = record
        
        if record.levelname == "WARNING":
            formatted.msg = color(record.msg, 33) # yellow
        
        if record.levelname == "ERROR" or record.levelname == "CRITICAL":
            formatted.msg = color(record.msg, 31) # red
        else:
            formatted.msg = record.msg

        logging.StreamHandler.emit(self, record)