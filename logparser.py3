#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :

# file: 'logparser.py3'
"""
'logparser.py' is typically used to process log files and retrieve IP
addresses which can then be considered for filtering using iptables. 
When used without command line options: IP addresses are collected 
from STDIN and reported to STDOUT.

usage:
  logparser.py --help
  logparser.py --version
  logparser.py  [-qvd] 
                [-r | -rr ]
                [--white <wfile>...] 
                [--black <bfile>...] 
                [--input <ifile>...] 
                [--output <ofile>]

Options:
  -h --help  Print the __doc__ string.
  --version  Print the version number.
  -r  How much to report about the IP addresses. 
          0 - just the addresses themselves.
          1 - addresses and number of times each one appeared.
          2 - addresses and number of appearances categorized.
  -d   Demographics: include location/origin of IP if possible.
  -q --quiet  Supress reporting of unexpected conditions.
              Specifically, any input files that either don't exist
              or don't contain any IP addresses.
  -v --verbose  Report any known ('white' or 'black') IPs 
                that have been removed from output.
  -w --white=<wfile>  Specify 0 or more files containing white listed IPs.
  -b --black=<bfile>  Specify 0 or more files containing black listed IPs.
  -i --input=<ifile>  Specify 0 or more input files [default: stdin]
                      If any are provided, stdin is ignored.
  -o --output=<ofile>  Specify output file.  [default: stdout]
                       If none is provided, output goes to stdout.

Any known IPs can be provided in files specified as containing either
'black' or 'white' listed IPs.  These are also read and any IP addresses 
found will NOT be included in the output.  (See the -v/--verbose option 
which causes this to be reported.) Typically this would be useful if you
have a 'white' list of known IPs you would definitely NOT want to block 
and/or if you had a 'black' list of already blocked IPs which you'd have 
no need to block again.  If you have in fact blocked your black listed
IPs, it should be impossible for any of them to show up in log files.

If any provided file(s) don't exist or don't contain any IP's, this 
will be reported unless the -q/--quiet option is selected.

If this scrolls too much, try piping to pager:
./logparser3.py | pager
"""

modifications_to_be_considered = """
PLAN: see         !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
http://docs.python.org/3/library/collections.html#collections.Counter
"""
from docopt import docopt
import sys
import akparser3

args = docopt(__doc__, version="logparser.py v0.0")

# input file type (itype) can be 'lf', 'wf', or 'bf' (input, white, black)
arg_file_types = [ "--input", "--white", "--black" ]
                    # Used by 'docopt' module.
lf = arg_file_types[0]  # log file
wf = arg_file_types[1]  # white file
bf = arg_file_types[2]  # black file

f_status_dic = {lf:{}, wf:{}, bf:{}}
# These are to keep track of existence of input files.
# Empty dicts are populated by count of IPs keyed by file name.
# This serves the purpose of making us aware if we are fed 
# files containing no IPs.

ipDic = {lf:{}, wf:{}, bf:{}}  #     !! ALL DATA !!
# Once the first IP address in an input file is discovered 
# (log file, or a white or black file)
# Values keyed by IP address will be:
#    IP_Class objects for log file input,
#    integer count for white and black files.

class IP_Class (object):
    """ Componenets of the ipDic keyed by the IP

    For now 'other' is just a space holder for other info to follow.
    """

    def __init__(self, other=None):
        self.n = 0
        self.other = other

    def __repr__(self):
        return "Report: n= %d."%(self.n, ) 

    def increment(self):
        self.n += 1

    def how_many(self):
        return self.n

    def add_other(self, args):
        pass

def process(line, f_type, f_name):
    ip_list = akparser3.list_of_IPs(line)
    if ip_list:
        if f_type == lf:  # More than first IP in log file is ignored.
            ip_list = [ip_list[0]]
        for ip in ip_list:
            junk = f_status_dic.setdefault(f_type, {})
            junk = f_status_dic[f_type].setdefault(f_name, 0)
            f_status_dic[f_type][f_name] += 1
            
            junk = ipDic.setdefault(f_type, {})
            if f_type==lf:
                junk = ipDic[f_type].setdefault(ip, 
                                    IP_Class(other=None)  )
                ipDic[f_type][ip].increment()
                ipDic[f_type][ip].add_other(None)
            else:   # f_type is white or black file.
                junk = ipDic[f_type].setdefault(ip, 0)
                ipDic[f_type][ip] += 1

# The following if/else statement might (after debugging) be better placed 
# at the end of the code, just before the outF.close() statement.
if args["--output"]=='stdout':
    outF = sys.stdout
else:
    outF = open(args["--output"], 'w', encoding='utf-8')

print(args)  ### Comment out after debugging.

for arg_file_type in arg_file_types:
    print("Processing file type '%s'...."%(arg_file_type, )  )
    for f_name in args[arg_file_type]:
        print("    Processing f_name '%s'..."%(f_name, )  )
        with open(f_name, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    process(line, arg_file_type, f_name)
                

# Finished gathering input.  Now must process:
# 1. keep track of any absent or devoid of IPs files.
#   'white', 'black' or input
# 2. keep track of any 'white' or 'black' IPs removed from output.
# 3. Only if '-r'>=2: check for category in input.
# and then ...
# Report according to options as follows:
# True or False options: 
#    --quiet: do not report unexpected conditions (non existent files or
#    files not containing IPs)
#    --verbose: report any 'white' or 'black' IPs that have been removed
#    from the output.
#    -d (demographics)  MORE PROCESSING
# Numeric option:
#    -r: 0..2
#        0:  address alone
#        1:  address and number of appearances
#        2:  address and number of appearances categorized.

for key in f_status_dic.keys():
    print("f_status_dic first level key '%s':"%(key, )  )
    print(f_status_dic[key])
    print('-----------------------------------------------')
print('End of f_status_dic report.\n')
print('\n==============================================\n')

for key in ipDic.keys():
    print("Values for first level key '%s' in ipDic:"%(key, ) )
    for k in ipDic[key].keys():
        # print("Type of ipDic[key][key] is: %s."%\
        #                     (type(ipDic[key][k]), )  )
        print("\t%s: %s"%(k, ipDic[key][k], ))

    print('-----------------------------------------------')

