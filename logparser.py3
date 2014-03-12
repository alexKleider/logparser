#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :

# file: 'logparser.py3'
"""
usage:
  logparser.py --help
  logparser.py --version
  logparser.py  [-c] [--white <wfile>] [--input <ifile>...] [--output <ofile>]

Options:
  -h --help  Print the __doc__ string.
  --version  Print the version number.
  -c --collect  Collect IP addresses.
  -w --white=<wfile>  Specify file containing whitelisted IPs.
  -i --input=<ifile>   Specify zero or more input files [default: stdin]
  -o --output=<ofile>  Specify output file [default: stdout]

logparser.py is typically used to process log files. 
IP addresses can be collected to be subsequently considered for black
listing.
A whitelisting file can be provided and any IP addresses found in that
file will be eliminated from the blacklist.  If the file doesn't exist
or happens not to contain any IP addresses, an error message will be
sent but this sill not effect program execution.
"""

from docopt import docopt
import sys

args = docopt(__doc__, version="logparser.py v0.0")

print (args)

def process(line):
    print(line.strip()),

for ifname in args["--input"]:
    if ifname=='stdin':
        for line in sys.stdin:
            process(line)
    else:
        with open(ifname, 'r', encoding="utf-8") as f:
            for line in f:
                process(line)


