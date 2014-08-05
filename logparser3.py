#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :
# file: 'logparser3.py'
"""'logparser3.py' is typically used to process log files and retrieve IP
addresses which can then be considered for filtering using iptables.
When used without command line options: IP addresses are collected
from STDIN and reported to STDOUT.

usage:
  logparser3.py --help
  logparser3.py --version
  logparser3.py  [-qvfd]
                [-r | -rr ]
                [--white <wfile>...]
                [--black <bfile>...]
                [--input <ifile>...]
                [--logdir <dir>...]
                [--output <ofile>]

Options:
  -h --help  Print the __doc__ string.
  --version  Print the version number.
  -r  How much to report about the IP addresses.
          0 - Addresses alone.
          1 - Addresses and number of times each one appeared.
          2 - Addresses, number of appearances, type of appearances,
              and additional information if available.
  -d --demographics  Include location/origin of IP if possible.
  -q --quiet  Supress reporting of success list, file access errors,
              or files devoid of IPs.
  -v --verbose  Report any known ('white' or 'black') IPs
                that have been removed from output.
  -w --white=<wfile>  Specify 0 or more files containing white listed IPs.
  -b --black=<bfile>  Specify 0 or more files containing black listed IPs.
  -i --input=<ifile>  Specify 0 or more input files [default: sys.stdin]
                      If any are provided, stdin is ignored.
                      These are typically log files but don't have to be.
  -l --logdir=<dir>   Specify 0 or more directories from which to include
                      log files (any file with 'log' in its name.) These
                      files will be appended to the list of files
                      specified by the '--input' option.
  -o --output=<ofile>  Specify output file.  [default: stdout]
                       If none is provided, output goes to stdout.
  -f --frequency   Sort output by frequency of appearance of IPs
                   (Default is by IP.)

Any known IPs can be provided in files specified as containing either
'--black' or '--white' listed IPs.  These are also read and any IP
addresses found will NOT be included in the output.  (See the
-v/--verbose option which causes this to be reported.) Typically this
would be useful if you have a 'white' list of known IPs you would
definitely NOT want to block and/or if you had a 'black' list of already
blocked IPs which you'd have no need to block again.
Keep in mind that it should not be possible to have a black listed IP
address appear in log files if it has in fact been blocked.

If any provided file(s) don't exist or don't contain any IP's, this
will be reported unless the -q/--quiet option is selected.

If this scrolls too much, try piping to pager:
./logparser3.py -h | pager
"""
######  END of USAGE statement.  ######
import sys
from docopt import docopt
import akparser3

### GLOBALS ###

args = docopt(__doc__, version="logparser3.py v0.2.2")
args['--input'].extend(akparser3.get_log_files(args['--logdir']))
if len(args['--input'])>1 and args['--input'][0]==sys.stdin:
    junk = args['--input'].pop(0)
_r_int = r = args['-r']
_d_bool = d = args['--demographics']
_q_bool = q = args['--quiet']
_v_bool = v = args['--verbose']
_f_bool = f = args['--frequency']
_l_list = l = args['--logdir']

# input file type (itype) can be 'lf', 'wf', or 'bf' (input, white, black)
arg_file_types = [ "--input", "--white", "--black" ]
    # The above listed strings are used as keys by the 'docopt' module.
lf = arg_file_types[0]  # log file
wf = arg_file_types[1]  # white file
bf = arg_file_types[2]  # black file

## Following 2 dicts are populated by process(line, f_type, f_name):

f_status_dic = {lf:{}, wf:{}, bf:{}}
# Keep track of existence of input files. Count of IPs keyed by file name.
# All IPs, including duplicates, are counted.
#             ------ file type  (f_type)
#             |   ----- file name  (f_name)
#             |   |
#             v   v
#f_status_dic{ } { } counter
#This keeps track of total number of IP addresses (including duplicates)
#found in each of the files processed.
#This information is used by empties_report()


ipDic = { }  #     !! ALL DATA !!
# Top level key is IP address.
# Next come dictionaries keyed by file type and then file name.
# Final values will be: IP_Class objects for log file input,
#                       integer counter for white and black files.
#      ----  IP address  (ip)
#      |   ----- file type  (f_type)
#      |   |   ----- file name  (f_name)
#      |   |   |
#      v   v   v
#ipDic{ } { } { } data: IP_Class objects for log file input,
#                       integer count for white and black files.

_unclassified_IP_indicator = 'solo-IP'
_absence_of_entry_indicator = '-'   ##### NOT BEING USED???

err_message_list = []
success_list = []
success_report = ''
debug_report ="DEBUGGING REPORT:"
def debug_append(s):
    global debug_report
    debug_report = '\n'.join((debug_report, s, ))

### END of GLOBAL DATA ### #

class IP_Class (object):
    """ End values of the ipDic for IPs in log file input.

    Also used as values in lists prepared for output.

    'other' is a dictionary keyed by log entry types with each value 
    being either an integer counter (for those with no associated data) 
    or a list if lists of strings providing the associated data.
    If it's the latter, (a list), the len() function provides a count.
    See akparser2.info() which is responsible for collecting the data
    and self.add_other() which inserts it into an instance of IP_Class.
    """

    #def __init__(self, ip, other=None):
    def __init__(self, ip):
        self.ip = ip
        self.n = 0
        self.other = {}
#        if other == None:
#            self.other = {}   # Dictionary to be keyed by an item found in
#                # akparser3.line_types or by <_unclassified_IP_indicator>
#                # If the later or a former which has no additional data,
#                # the value is a counter.  Otherwise a list of lists
#                # containing the data.
#        else:      # No occassion to use this so far.
#            self.other = other

    def display(self, r, d):
        """ What we choose to display depends on params 'r' and 'd'.

        [1] args["-r"] provided as parameter 'r', which is 
        an integer between 0 and 2 inclusive,          and 
        [2] args["--demographics"] provided as parameter 'd', 
        a Boolean."""
        report = \
        '{0: ^16}  {{0: ^5}}\n{{1}}{{2}}'.format(self.ip, self.n)
    #     ^          ^          ^    ^  
    #     |          |          |    | 
    #     |          |          |    >> additional report.
    #     |          |          >> demographic report.
    #     |          >> occurences  <--  self.n
    #     >> IP address
        occurences_report = ''
        additional_report = ''
        demographic_report = ''
        if r:  # r > 0          
            occurences_report = str(self.n)
        if r >=2:
            key_list = list(self.keys())
            key_list.sort()
            for line_type in key_list:
                additional_report += "{0: >33}:  {{0}}\n".\
                                            format(line_type)
                if type(self.other[line_type])==int:
                    additional_report = \
                                additional_report.format(self.other[line_type])
                else:
                    n = 0
                    for item in self.other[line_type]:
                        additional_report += "{0: >51}\n".format(item)
                        n += 1
                    additional_report = additional_report.format(n)
        if d:
            demographic_report = "\t{0[Country]}  {0[City]}\n".format\
                                                (akparser3.ip_info(self.ip))
        report = report.format(occurences_report,  # {0}
                               demographic_report, # {1}
                               additional_report)  # {2}
        return report

    def join(self, instance):
        assert self.ip == instance.ip,\
                "IP_Class.join() can not be called on non matching IPs."
        assert type(instance) == IP_Class,\
                "IP_Class.join() can only join another instance."
        assert type(self.other) == type(instance.other),\
                "IP_Class.join() can only join compatible instances."
        self.n += instance.n
        self_set = set(self.keys())
        instance_set = set(instance.keys())
        overlaps = self_set & instance_set
        new = instance_set - self_set
        for key in overlaps:  # Works for both int and lists:
            self.other[key] += instance.other[key]  
        for key in new:
            self.other[key] = instance.other[key]

    def increment(self):
        self.n += 1

    def how_many(self):
        return self.n

    def add_other(self, args):
        """ This method is set up to deal with the results of
        akparse3.get_log_info(line) which returns a tuple:
        (log_entry_type, data_gleaned, )   or None.
        None indicates that no log_entry_type was recognized.
        Whether or not an IP was found is not relevant but we use it
        in the context that one has been found.
        <data_gleaned> is None if no data exists, or a list if it does.
        This method populates 'other'.
        """
        #print("add_other() received {0}".format(args) )
        if not args:
            args = (_unclassified_IP_indicator, None, )
        if not args[1]:
            junk = self.other.setdefault(args[0], 0)
            self.other[args[0]] += 1
        else:
            junk = self.other.setdefault(args[0], [])
            self.other[args[0]].append(args[1])

    def get_log_count(self):  # Shouldn't be necessary, already in self.n
        global debug_report 
        debug_report += "{0} <self.other> is {1}\n".\
                                format(self.ip, self.other) 
        n = 0
        for item in self.other:
            if type(self.other[item])==int:
                n += self.other[item]
            else:
                n += len(self.other[item])
        return n

    def keys(self):
        return list(self.other)

    def values(self, key):
        return(self.other[key])
##### End of Class_IP declaration. #####

def order_by_frequency(ip):  
    """ A KEY function using [ip][lf] as index into ipDic.

    Returns a tuple suitable for use as a key to sort a list of 
    IP's by number of times they appear in input log files with 
    the IP itself as the secondary key. 
    """
    n =  0
    for file_name in ipDic[ip][lf]:
        n += ipDic[ip][lf][file_name].how_many()
        # c += ipDic[ip][lf][file_name].get_log_count()
    return (n, ip, )

def process(line, f_type, f_name):
    """This function populates f_status_dic and ipDic.
    i.e. it HAS SIDE EFFECTS on those two globals. 
    It ignores lines that do not contain an IP address but by the same
    token, it can be assumed that if there is any action, it is because an
    IP address exists in the line."""
    global f_status_dic 
    global ipDic
    ip_list = akparser3.list_of_IPs(line)
    #print("process() got the following IPs: {0}.".format(ip_list) )
    if ip_list:
        if (f_type == lf) and (len(ip_list)>1):  
            # Get rid of reverse look up version of IP.
            ip_list = [ip_list[1]]
            #print("..and changed it to {0}".format(ip_list) )
        for ip in ip_list:
            junk = f_status_dic.setdefault(f_type, {})
            junk = f_status_dic[f_type].setdefault(f_name, 0)
            f_status_dic[f_type][f_name] += 1
            #print("Incrimenting '{0}'/'{1}' f_status_dic.".\
                        #format(f_type, f_name) )
            
            junk = ipDic.setdefault(ip, {})
            junk = ipDic[ip].setdefault(f_type, {})
            if f_type==lf:
                other = akparser3.get_log_info(line)  # Data entered ...
                junk = ipDic[ip][f_type].setdefault(f_name, IP_Class(ip) )
                ipDic[ip][f_type][f_name].increment()
                #print("Incrimenting '{0}'/'{1}' ipDic.".\
                        #format(f_type, f_name) )
                ipDic[ip][f_type][f_name].add_other(other)  # & here.
            else:   # f_type is white or black file: just increment.
                junk = ipDic[ip][f_type].setdefault(f_name, 0)
                ipDic[ip][f_type][f_name] += 1

def empties_report(f_status_dic):
    """ Returns a report of input files containing no IP addresses.
    
    Returns empty string if none found."""
    ret = ""
    tups = []
    for f_type in f_status_dic.keys():
        for f_name in f_status_dic[f_type]:
            if f_status_dic[f_type][f_name] == 0:
                tups.append((f_name, f_type, )  )
    if tups:
        ret += '\nFILES WITHOUT IP ADDRESS\n'
        for tup in tups:
            ret += "\t'{0[1]}' (of type '{0[0]}')\n".format(tup)
    return ret

def create_sets_by_tuple(ipDic):
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

def raw_output_set(sets):
    """Returns the set of IPs in input/log files."""
    ret_set = set()
    for f_type, f_name in sets.keys():
        if f_type == "--input":
            ret_set |= sets[(f_type, f_name, )]
    return ret_set

def create_output_class_list(output_collection):
    """Sets up the list of IP_Class instances for output.
    
    Assumes output_collection contains IPs that were found 
    in an input log file and therefore will have IP_Class 
    instances associated with corresponding entries in ipDic.
    Note that 'output_collection' can be any iterable whose 
    values are IPs that exist in ipDic with a log file index.
    """
    output_list = []
    for ip in output_collection:
        # join them:
        item_4_list = IP_Class(ip)
        for f_name in ipDic[ip][lf]:
            item_4_list.join(ipDic[ip][lf][f_name])
        output_list.append(item_4_list)
    return output_list

def remove_overlaps_report(sets, output_set, r, d):
    """Returns report of overlapping IPs; removes them from output_set.
    
    Checks for IPs in output_set that are also in white or black input 
    files. Any such IPs are reported and removed from output_set. 
    Note: THIS IS A SIDE EFFECT on output_set.
    Returned is either the report, or an empty string.
    Parameters 'r' & 'd' (from <args>) determine how much to report.
    """
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
    list_of_overlapping_instances = create_output_class_list(overlaps)
    if overlaps_by_file:
        ret = ret + \
"""The following IP addresses are being removed from the output 
 because they appear in white or black input files as shown:
"""
        for tup in overlaps_by_file:
            ret = ret + \
"""#     Contents of file '{0[1]}' (type '{0[0]}'):
""".format(tup)
            ips = sorted(overlaps_by_file[(tup)], key=akparser3.sortable_ip)
            for ip in ips:
                ip_class_instance = ipDic[ip][tup[0]][tup[1]]
                ret += "        {0}\n".format(ip)
        output_set -= overlaps
        if (r or d):
            ret += "Requested details follow:\n"
            for instance in list_of_overlapping_instances:
                ret += instance.display(r, d)
    return ret

####***************  __main__  begins here.  ***************#####

print(args)  ### Comment out after debugging.

for arg_file_type in arg_file_types:
    for f_name in args[arg_file_type]:
        #print("Processing f_name: '{0}'".format(f_name) )
        if f_name == 'sys.stdin':
            f = sys.stdin
        else:
            try:
                f = open(f_name, 'r', encoding='utf-8')
            except IOError as err_report:
                err_message_list.append(err_report)
                continue
        for line in f:
            line = line.strip()
            if line:
                process(line, arg_file_type, f_name)
        if f_name != 'sys.stdin':
            f.close()
        success_list.append(f_name)

# print(f_status_dic)

if success_list and not q:
    success_report += \
    '\nThe following files were successfully opened for input:\n'
    for f_name in success_list:
        success_report += '\t{0}\n'.format(f_name)
    success_report += '\n'

report = '## LogParse REPORT ##\n{0}'.format(success_report)

if not q:
    # report non-existent files.
    if err_message_list:
        report += '\nFILE ACCESS ERRORS:\n'
        for message in err_message_list:
            report += '{0}\n'.format(message)
        report += 'End of file access errors report.\n'
    # report files devoid of IP addresses.
    report += '{0}\n'.format(empties_report(f_status_dic))

sets_by_tuple =  create_sets_by_tuple(ipDic)
output_set = raw_output_set(sets_by_tuple)  # Likely modified by next line.
duplicate_deletion_report = \
            remove_overlaps_report(sets_by_tuple, output_set, r, d)
if v:
    # report 'white' or 'black' IPs removed from output.
    report += duplicate_deletion_report

report += '\n## MAIN BODY of OUTPUT ##\n'
report += "__ IP Address __  _ # _   _Line Type  +/- extra info\n"
ips = list(output_set)
if f:
    ips.sort(key=order_by_frequency, reverse=True)
else:
    ips.sort(key=akparser3.sortable_ip)
class_list = create_output_class_list(ips)

for instance in class_list:
    report += instance.display(r, d)

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
outF.write("\n{0}\n".format(debug_report))
outF.close()

notes =\
"""
# After input is collected must process:
# 1. keep track of any absent (err_message_list = [<list>])
                    or devoid of IPs (empties_report) files.
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

empties_report() Reports files devoid of IP addresses. 
create_sets_by_tuple()  dictionary keyed by (f_type, f_name, )
                          vaues are sets of IP addresses.
raw_output_set(sets) Returns the set of IPs in input/log files.
remove_overlaps_report(sets, ouput_set, r, d):
    Checks to see if any IPs already in white or black input files 
    appear in the proposed output_set. Any such IPs are reported and 
    removed from output_set. Returned is either the report, or None.
"""
"""
traverse through command line file arguments:
arg_file_type in arg_file_types:
    for f_name in args[arg_file_type]:
"""

