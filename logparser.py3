#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :
# file: 'logparser.py3'
"""'logparser.py' is typically used to process log files and retrieve IP
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
          0 - Address alone.
          1 - Addresses and number of times each one appeared.
          2 - Addresses, number of appearances, type of appearances,
              and additional information if available.
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
                      These are typically log files but don't have to be.
  -o --output=<ofile>  Specify output file.  [default: stdout]
                       If none is provided, output goes to stdout.

Any known IPs can be provided in files specified as containing either
'--black' or '--white' listed IPs.  These are also read and any IP 
addresses found will NOT be included in the output.  (See the 
-v/--verbose option which causes this to be reported.) Typically this 
would be useful if you have a 'white' list of known IPs you would 
definitely NOT want to block and/or if you had a 'black' list of already 
blocked IPs which you'd have no need to block again. 
#
If any provided file(s) don't exist or don't contain any IP's, this 
will be reported unless the -q/--quiet option is selected.

If this scrolls too much, try piping to pager:
./logparser3.py | pager
"""
######  END of USAGE statement.  ###########

modifications_to_be_considered = """
PLAN: see         !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
http://docs.python.org/3/library/collections.html#collections.Counter
"""
import sys
from docopt import docopt
import akparser3

### Configuration area ###

args = docopt(__doc__, version="logparser.py v0.1.0")

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

ipDic = { }  #     !! ALL DATA !!
# Top level key is IP address.
# Next come dictionaries keyed by file type and then file name.
# Final values will be:
#    IP_Class objects for log file input,
#    integer count for white and black files.

## The above two dictionaries are globals
## populated by process(line, f_type, f_name).

_unclassified_IP_indicator = 'solo-IP'
_absence_of_entry_indicator = '-'

err_message_list = []
success_list = []

### END of CONFIGURATION AREA ### #

class IP_Class (object):
    """ End values of the ipDic for IPs in log file input.

    'other' is a dictionary keyed by log entry types (which might be
    'None' if entry type is unrecognized) with each value consisting 
    of a list (possibly empty) of strings (possibly empty) providing the
    information gleaned from each instance of the particular entry type.
    See akparser2.info() which is responsible for collecting the data
    and self.add_other() which inserts it into an instance of IP_Class.
    """

    def __init__(self, other=None):
        self.n = 0
        self.other = {}   # Dictionary to be keyed by an item
                          # found in akparser3.line_types

    def __repr__(self):
        """Need to think about this.  So far it's only been of use for
        debugging."""
        return """Report: n= %d and 'other' is as follows...
            %s"""%(self.n, self.other) 

    def increment(self):
        self.n += 1

    def how_many(self):
        return self.n

    def add_other(self, args):
        """ This method is set up to deal with the results of
        akparse3.get_log_info(line) which returns a tuple:
        (log_entry_type, data_gleaned, )   or None """
        if not args:
            args = (_unclassified_IP_indicator, [], )
        junk = self.other.setdefault(args[0], [])
        if args[1]:
            self.other[args[0]].append(args[1])

    def keys(self):
        return list(self.other)

    def values(self, key):
        return(self.other[key])
#
def process(line, f_type, f_name):
    """This function populates f_status_dic and ipDic.
    i.e. it HAS SIDE EFFECTS on those two globals. """
    ip_list = akparser3.list_of_IPs(line)
    if ip_list:
        if f_type == lf:  # More than first IP in log file is ignored.
            ip_list = [ip_list[0]]
        for ip in ip_list:
            junk = f_status_dic.setdefault(f_type, {})
            junk = f_status_dic[f_type].setdefault(f_name, 0)
            f_status_dic[f_type][f_name] += 1
            
            junk = ipDic.setdefault(ip, {})
            junk = ipDic[ip].setdefault(f_type, {})
            if f_type==lf:
                other = akparser3.get_log_info(line)
                junk = ipDic[ip][f_type].setdefault(f_name, IP_Class() )
                ipDic[ip][f_type][f_name].increment()
                ipDic[ip][f_type][f_name].add_other(other)
            else:   # f_type is white or black file.
                junk = ipDic[ip][f_type].setdefault(f_name, 0)
                ipDic[ip][f_type][f_name] += 1

def report_empties(f_status_dic):
    """ Returns None, or, if found, a report of
    files in which IP addresses were not found."""
    tups = []
    for f_type in f_status_dic.keys():
        for f_name in f_status_dic[f_type]:
            if f_status_dic[f_type][f_name] == 0:
                tups.append((f_name, f_type, )  )
    if tups:
        report = \
            "The following files failed to yield any IP address(es.)\n"
        for tup in tups:
            report += "\t'{0[1]}' (of type '{0[0]}')\n".format(tup)
        return report

def create_sets(ipDic):
    """Returns a dictionary of sets, 
    one for each (f_type, f_name, ) combination and 
    containing the IPs gleaned from that particular file."""
    sets = {} 
    for ip in ipDic:
        for f_type in ipDic[ip]:
            for f_name in ipDic[ip][f_type]:
                tup = (f_type, f_name, )
                junk = sets.setdefault(tup, set()  )
                sets[tup].add(ip)
    return sets
#
def raw_output_set(sets):
    """Returns the set of IPs in input/log files."""
    ret_set = set()
    for f_type, f_name in sets.keys():
        if f_type == "--input":
            ret_set |= sets[(f_type, f_name, )]
    return ret_set

def report_remove_overlapping_sets(sets, output_set):
    """Checks to see if any IPs already in white or black input files 
    appear in the proposed output_set. Any such IPs are reported and 
    removed from output_set. Returned is either the report, or None.
    Note the intended side effect on output_set"""
    ret = ""
    overlaps_by_file = {}  # Using a dict (vs set) to keep track of files.
    overlaps = set()
    for tup in sets.keys():
        f_type, f_name = tup
        if f_type != "--input":   # Must be white or black.
            if not sets[tup].isdisjoint(output_set):  # Common IP exists.
                junk = overlaps_by_file.setdefault(tup, set())
                overlap =  output_set & sets[tup]
                overlaps |= overlap
                overlaps_by_file[tup] |= overlap
                print("File '{0[1]}' ('{0[0]}': {1}"\
                        .format(tup, overlap) )
    if overlaps_by_file:
        print(" The following overlaps have been discovered:\n{0}"\
                                        .format(overlaps_by_file)   )
        ret = ret + \
"""# The following IP addresses are being removed from the output 
# because they appear in white or black input files as shown:
"""
        for tup in overlaps_by_file:
            ret = ret + \
"""#     Contents of file '{0[1]}' (type '{0[0]}'):
""".format(tup)
            ips = sorted(overlaps_by_file[(tup)], key=akparser3.sortable_ip)
            for ip in ips:
                ret += "        {0}\n".format(ip)
            #output_set.remove(ip)
            print('Just removed {0} from output_set.'.format(ip))
        output_set -= overlaps
        return ret

#####***************  __main__  begins here.  ***************#####

# print(args)  ### Comment out after debugging.
#
for arg_file_type in arg_file_types:
    #print("Processing file type '%s'...."%(arg_file_type, )  )
    for f_name in args[arg_file_type]:
        #print("    Processing f_name '%s'..."%(f_name, )  )
        try:
            with open(f_name, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        process(line, arg_file_type, f_name)
        except IOError as err_report:
            err_message_list.append(err_report)
            continue
        success_list.append(f_name)

#print("*** {0}".format(ipDic.keys())  )

#for key in f_status_dic.keys():
#    print("f_status_dic first level key '%s':"%(key, )  )
#    print(f_status_dic[key])
#    print('-----------------------------------------------')
#print('End of f_status_dic report.\n')
#print('\n==============================================\n')

#ips = ipDic.keys()
#print("^^^ keys of ipDic are: {0}".format(ips)  )
#for ip in ips:
#    print("Values for ip key '%s' in ipDic:"%(ip, ) )
#    f_types = ipDic[ip].keys()
#    for f_type in f_types:
#        print("    Values for f_type '%s' in ipDic:"%(f_type, ) )
#        f_names = ipDic[ip][f_type].keys()
#        for f_name in f_names:
#            print("      Values for f_name '%s' are: "%(f_name, ))
#            if f_type == lf:
#                line_types = ipDic[ip][f_type][f_name].keys()
#                for line_type in line_types:
#                    print("\t%s: "%(line_type, ))
#                    print("\t  %s"%\
#                        (ipDic[ip][f_type][f_name].values(line_type),) )
#                    print()
#            else:
#                print("    Count is %s."%(ipDic[ip][f_type][f_name], )  )
#
#    print('-----------------------------------------------')
### END OF DEBUGGING CODE SECTION #### 

report = '## LogParse REPORT ##\n'

if not args["--quiet"]:
    # report non-existent files.
    if err_message_list:
        report += '\nFILE ACCESS ERRORS:\n'
        for message in err_message_list:
            report += '{0}\n'.format(message)
        report += 'End of file access errors report.\n'
    # report files devoid of IP addresses.
    empties_report = report_empties(f_status_dic)
    if empties_report:
        report += '\nFILES WITHOUT IP ADDRESS\n'
        report += '{0}\n'.format(empties_report)

sets =  create_sets(ipDic)
output_set = raw_output_set(sets)  # Likely modified by next line.
duplicate_deletion_report = \
            report_remove_overlapping_sets(sets, output_set)
if args["--verbose"] and duplicate_deletion_report:
    # report 'white' or 'black' IPs removed from output.
    report += '\n'
    report += duplicate_deletion_report

report += '\n## MAIN BODY of OUTPUT ##\n'
report += "__ IP Address __  _ # _   _Line Type  +/- extra info\n"
ips = list(ipDic)
ips.sort(key=akparser3.sortable_ip)
#
for ip in ips:
    if lf in ipDic[ip].keys() and ip in output_set:
        report += '{0: ^16}  {{0: ^5}}\n{{1}}{{2}}'.format(ip)
        occurences_report = ''
        demographic_report = ''
        additional_report = ''
        if args["-r"] > 0:
            n = 0
            for f_name in ipDic[ip][lf].keys():
                n += ipDic[ip][lf][f_name].how_many()
                if args["-r"] > 1:
                    line_types = sorted(ipDic[ip][lf][f_name].keys())
                    #line_types.sort()
                    for line_type in line_types:
                        additional_report += \
                        "{0: >36}:\n".format\
                                                            (line_type)
                        for entry in\
                                ipDic[ip][lf][f_name].values(line_type):
                            if entry:
                                additional_report +=\
                                "{0: >52}\n".format\
                                                              (entry)
            occurences_report = str(n)
        if args["-d"]:
            demographic_report = \
            "\t{0[Country]}  {0[City]}\n".format\
            (akparser3.ip_info(ip))
        report = report.format(occurences_report,
                               demographic_report,
                               additional_report)

if args["--output"]=='stdout':
    outF = sys.stdout
else:
    try:
        outF = open(args["--output"], 'w', encoding='utf-8')
    except IOError as err_report:
        print("Unable to open output file '{0}'.".\
                                            format(args["--output"]) )
        print("Error report: '{0}'.".format(err_report))
        print("Out put is being sent instead to stdout.")
        outF = sys.stdout
outF.write(report)
outF.close()
#

notes =\
"""
# After input is collected must process:
# 1. keep track of any absent (err_message_list = [<list>])
                    or devoid of IPs (report_empties) files.
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
             ------ file type  (f_type)
             |   ----- file name  (f_name)
             |   |
             v   v
f_status_dic{ } { } counter
This keeps track of total number of IP addresses (including duplicates)
found in each of the files processed.
This information may be redundant- may have all we need already in ipDic.
!! But before deleting it, remember that it is used by report_empties() !!

      ----  IP address  (ip)
      |   ----- file type  (f_type)
      |   |   ----- file name  (f_name)
      |   |   |
      v   v   v
ipDic{ } { } { }  data- for black and white files: a simple counter
                        for input (log) files: an instance of IP_Class
#

IP_Class provides:
  * a counter accessible using methods incriment() and how_many()
  * 'other' which is a dictionary keyed by line_types
     with values which are lists of lists containing log info.
     These a accessed using methods
     add_other(tuple: (log_entry_type, list_of_values, ) )
     keys()  # returns the keys (log_entry_types)
     values(key: a log_entry_type)  
        # returns a list of lists
        # one list for each instance of the key found 
        # in the log files.

report_empties() Reports files devoid of IP addresses. 
create_sets()  dictionary keyed by (f_type, f_name, )
                          vaues are sets of IP addresses.
raw_output_set(sets) Returns the set of IPs in input/log files.
report_remove_overlapping_sets(sets, ouput_set):
    Checks to see if any IPs already in white or black input files 
    appear in the proposed output_set. Any such IPs are reported and 
    removed from output_set. Returned is either the report, or None.
"""
"""
traverse through command line file arguments:
arg_file_type in arg_file_types:
    for f_name in args[arg_file_type]:
"""
    
