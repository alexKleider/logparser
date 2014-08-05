#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :

# file: 'akparser3.py'
"""
A module to support parsing of log files.

* website?     # Perhaps some day.
* Repository: https://github.com/alexKleider/logparser
* Licensed under terms of GPL latest version.
* Author: Alex Kleider, alex@kleider.ca 2014

Parses log files:  To date, can handle:
        auth.log   and 
        fail2ban.log  .
Other logs can be added by request to author. (See (c) statement.)

Usage: 
    import akparser3
    ...
    Provides the following:  i.e. Here is the API.

    ip_info(ip_address)
        # Returns   a dictionary keyed by
        # 'Country', 'City', 'Lat', 'Lon', 'IP'
        # TO DO: provide error checking.
    list_of_IPs(line)
        # An re.compile(..).findall function
        # Returns a list.  (i.e. Allows input to contain >1 IP/line.)
        # Generally log files report only one IP per line unless a 
        # reverse look up is provided in which case the second one
        # is the same IP but with the dotted quads in reverse order.
    line_types: a list of strings. Provides our SPoL [1]
    get_log_info(line)
        # Returns a tuple: line_type, data_gleaned.  
        #     line_type: one of the strings provided in line_types.
        #     data_gleaned: a list, possibly empty.
        #          Currently there is never >1 item in the list.
        # Returns None if line is not a recognized log entry.
    get_header_text(line_type)  
        # line_type: one of the strings provided in line_types.
        # Returns a string thus providing a mechanism for providing 
        # line_type specific information: this might be useful when 
        # presenting output.
    get_log_files(dir_iterable)
        # accepts an iterable of directory names.
        # returns a list of all file names containing '.log'.
    sortable_date(line)
        # Deals with two issues:
        #   1. Date representations differ.
        #   2. We want to be able to sort by date.
        # Looks to find something that can be interpreted as a date
        # which is then returned in format 'yyyy-mm-dd hh:mm:ss'
        # (Suitable for sorting.)
        # Deals with date formats used by auth.log and by fail2ban.
        # Might have to add code to add support for other log file
        # types if their dates are presented differently. 
        # Returns None if parsing is unsuccessful.
    sortable_ip(ip)
        # Useful as a key function for sorting.
        # Quietly returns None if parameter is bad.

"""

__all__ = ['list_of_IPs', 
          'Ip_Demographics',
          'line_types',
          'get_log_info',
          'get_header_text',
          'get_log_files',
          'sortable_date',
          'sortable_ip'
          ]
__version__ = '0.2.5'

import re
import os
import urllib.request
import datetime

line_types = ['invalid_user',   'no_id',     'break_in', 
              'pub_key',        'closed',    'disconnect', 
              'listening',      'ban',       'unban', 
              'already_banned'                            ]
# BEGINNING of SECTION which DEPENDS on line_types
# and therefore will have to be modified if any 
# changes are made to line_types.
re_format = {}         # } All keyed
re_search4 = {}        # } by items
keys_provided = {}     # } found in
header_text = {}       # } 'line_types'.

# Expressions relevant to auth.log:
re_format["invalid_user"] = \
    r"""Invalid user (?P<user>\S+) from """
header_text["invalid_user"] = "'auth.log' reporting 'invalid user's:"
re_format["no_id"] = \
    r"""Did not receive identification string from \S+"""
header_text["no_id"] = "'auth.log' reporting 'no id's:"
re_format["break_in"] = r"POSSIBLE BREAK-IN ATTEMPT!"
header_text["break_in"] = \
    "'auth.log' reporting 'POSSIBLE BREAK-IN ATTEMPT!'s:"
re_format["pub_key"] = r""" Accepted publickey for (?P<user>\S+)"""
header_text["pub_key"] = "'auth.log' reporting ''s:"
re_format["closed"] = r""" Connection closed by \S+"""
header_text["closed"] = "'auth.log' reporting 'closed's:"
re_format["disconnect"] = r""" Received disconnect from (?P<who>[.\w+]):"""
header_text["disconnect"] = \
    "'auth.log' reporting 'Received disconnect from's:"
re_format["listening"] = r""" Server listening on (?P<listener>.+)"""
header_text["listening"] = "'auth.log' reporting 'Server listening on's:"

# fail2ban.log lines:
re_format["ban"] = \
    r"fail2ban\.actions: WARNING \[ssh\] Ban "
header_text["ban"] = "'fail2ban' reporting 'ban's:"
re_format["unban"] = \
    r"fail2ban\.actions: WARNING \[ssh\] Unban "
header_text["unban"] = "'fail2ban' reporting 'unban's:"
re_format["already_banned"] = r" already banned$"
header_text["already_banned"] = "'fail2ban' reporting 'already banned's:"
# SECTION which DEPENDS on 'line_types' CONTINUES...
for key in line_types:
    re_search4[key] = re.compile(re_format[key]).search

keys_provided["invalid_user"] = ["user"]
keys_provided["no_id"] = []
keys_provided["break_in"] = []
keys_provided["pub_key"] = ["user"]
keys_provided["closed"] = []
keys_provided["disconnect"] = ["who"]
keys_provided["listening"] = ["listener"]

keys_provided["ban"] = []
keys_provided["unban"] = []
keys_provided["already_banned"] = []
# END of SECTION which DEPENDS on 'line_types'.

def get_header_text(line_type):
    """Return header text appropriate to line type."""
    return header_text[line_type]

def get_log_info(line):
    """Returns 'None' if not a recognized log entry  or
    a tuple: line_type, data_gleaned.  The later is a list if
    there is data gleaned, None if not.
    """
    for line_type in line_types:  # Assume a line can only be of 1 type.
        search_result = re_search4[line_type](line)
        if search_result:
            data_gleaned = []
            info_provided = keys_provided[line_type]
            if info_provided:  # Possibly empty list, unlikely >1 item.
                for item in info_provided:
                    data_gleaned.append(search_result.groups(item))
            else:
                data_gleaned = None
            return (line_type, data_gleaned, )
    return  # Redundant but makes the point that None is returned if
            # the line is not recognized as a known log line type.
#################################################################

# To identify IP addresses (ipv4.)
ip_exp = \
r"""
\b
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
"""
list_of_IPs = re.compile(ip_exp, re.VERBOSE).findall
# list_of_Ips(line) returns a list (could be empty) of IP addresses.

#################################################################
# To get demographic info regarding an IP address:

class Ip_Demographics(object):

    urls = ("hostip",
            "addgadgets",
            )

    url_dict = {\
        urls[0] : \
            "http://api.hostip.info/get_html.php?ip={0}&position=true",
        urls[1] : \
            "http://addgadgets.com/ipaddress/index.php?ipaddr={0}"
        }

#url_format_str = \
#"http://api.hostip.info/get_html.php?ip={0}&position=true"

charset_re = r"""\bcharset="(?P<encoding>[-\w]+)"""
get_encoding = re.compile(charset_re).search

info_re_dict = {\
    urls[0] : r"""
        Country:[ ](?P<country>.*)
        [\n]
        City:[ ](?P<city>.*)
        [\n]
        [\n]
        Latitude:[ ](?P<lat>.*)
        [\n]
        Longitude:[ ](?P<lon>.*)
        [\n]
        IP:[ ](?P<ip>.*)
        """                ,
    urls[1] : r"""
        \bcharset="(?P<encoding>[-\w]+)"
        .+?
        (?P<IP>[0-9]{1,3}(?:[.][0-9]{1,3}){3})
        .+?
        Country:&nbsp;</td><td>
        (?P<Country>[ \w]+)
        .+?
        Region:&nbsp;</td><td>
        (?P<Region>[ \w]+)
        .+?
        City:&nbsp;</td><td>
        (?P<City>[ \w]+)
        .+?
        Latitude:&nbsp;</td><td>
        (?P<Lat>[-]?[.\d]+)
        .+?
        Longitude:&nbsp;</td><td>
        (?P<Lon>[-]?[.\d]+)
        .+?
        ISP[ ]name:&nbsp;</td><td>
        (?P<ISP>[ .\w]+)
        .+?
        Organization[ ]name:&nbsp;</td><td>
        (?P<OrgName>[ .\w]+)
        """
    }

    get_demographics_dict = {\
        urls[0] : re.compile(info_re_dic[urls[0]],
                            re.VERBOSE + re.DOTALL),
        urls[1] : re.compile(info_re_dic[urls[1]],
                            re.VERBOSE + re.DOTALL)
                            }

#   get_IP_demographics = re.compile(info_exp, re.VERBOSE).search

    def ip_info(ip_address):
        """
    Returns a dictionary keyed by Country, City, Lat, Lon, IP  and err.

    Depends on http://api.hostip.info (which returns the following:
    'Country: UNITED STATES (US)\nCity: Santa Rosa, CA\n\nLatitude:
    38.4486\nLongitude: -122.701\nIP: 76.191.204.54\n'.)
    THIS WILL BREAK IF THE WEB SITE CHANGES OR GOES AWAY!!!
    err will empty string unless there is an urllib.request.URLError
    in which case, it will contain the error and the other values will
    be empty strings.
    """
        try:  # 16 lines in this try statement.
            # A file-like object is returned by the request:
            f_response =  urllib.request.urlopen(url_format_str %\
                                           (ip_address, ))
        except urllib.request.URLError as err_report: 
            return {"Country" : "",
                    "City" : "",
                    "Lon" : "",
                    "IP" : "",
                    "err" : err_report              }
        ip_metadata = str(f_response.info()) # The returned Headers.
        encoding_group = get_encoding(ip_metadata) # Using my re function.
        encoding = encoding_group.group("charset")

        ip_demographics = f_response.read()  # The returned Data.
        ip_demographics = ip_demographics.decode(encoding,
                                                "backslashreplace.")
        info = get_IP_demographics(ip_demographics)
        return {"Country" : info.group("country"),
                "City" : info.group("city"),
                "Lat" : info.group("lat"),
                "Lon" : info.group("lon"),
                "IP" : info.group("ip"),
                "err" : ""                           }
    # End of IP demographics gathering section.
#################################################################

def sortable_ip(ip):
    """Takes am IP address of the form 50.143.75.105
    and returns it in the form 050.143.075.105.
    ... useful as a key function for sorting.
    Quietly returns None if parameter is bad."""
    parts = ip.strip().split('.')
    if not len(parts)==4:
        return None
    else: 
        return "{0[0]:0>3}.{0[1]:0>3}.{0[2]:0>3}.{0[3]:0>3}".format(parts)

# Some date routines to provide sortable_date().

ThisYear = datetime.date.today().year
ThisMonth = datetime.date.today().month

def _sampleYR(samplemonth):
    """ auth.log provides date without the year 
        so we have to "guess."  """
    tmonth = ThisMonth
    while tmonth > 0:
        if samplemonth == tmonth:
            return ThisYear
        tmonth -= 1
    return ThisYear -1


months = {"Jan" : 1, "Feb" : 2, "Mar" : 3, "Apr" : 4,
          "May" : 5, "Jun" : 6, "Jul" : 7, "Aug" : 8,
          "Sep" : 9, "Oct" : 10, "Nov" : 11, "Dec" : 12  }

def sortable_date(log_line):
    """ Needs to handle all types of log lines. 
        Currently can handle those of: auth.log fail2ban. 
        Returns None if parsing is unsuccessful."""
    try:   # auth.log 
        l = log_line[:15].split()
        return  "%s-%02d-%02d %s" % \
            (_sampleYR(int(months[l[0]])), 
            months[l[0]], 
            int(l[1]), l[2], )
    except:
        failed = True
    try:  # fail2ban.log
        l = log_line[:10].split('-')
        return "%s-%s-%s %s" %\
            (l[0], l[1], l[2], log_line[11:19], )
    except:
        return

def get_log_files(dir_iterable):
    """Takes an iterable, assumed to be a list of directories,
    and traverses these directories recursively returning a
    a list of all the file names containing the string '.log'. 
    The heavy lifting is done by os.walk which silently does 
    nothing if given a directory that does not exist.
    """
    log_files = []
    for directory in dir_iterable:
        for dir_name, dir_list, file_list in os.walk(directory):
            for file_name in file_list:
                if '.log' in file_name:
                    d_n = dir_name
                    while d_n[-1:]=='/':  # To eliminate double slashes.
                        d_n = d_n[0:-1]
                    log_files.append('{0}/{1}'.format(d_n, file_name))

                    #print("Directory '{0}':".format(item[0]))
                    #print("\t{0}".format(l1))
    return log_files

if __name__=="__main__":
    print("Running Python3 script: 'akparser3.py'.......")
    import sys
    t2 = \
"""Dec 23 05:17:01 localhost CRON[17407]: pam_unix(cron:session): session closed for user root
""" 
    t2 = \
"""2013-11-26 06:22:53,863 fail2ban.actions: WARNING [ssh] 204.68.120.92 already banned
2013-12-30 01:17:43,514 fail2ban.actions: WARNING [ssh] Ban 213.20.227.137
Dec 23 06:08:41 localhost sshd[17416]: Address 221.204.245.144 maps to 144.245.204.221.adsl-pool.sx.cn, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!
Dec 22 22:18:07 localhost sshd[17238]: Invalid user ro from 133.242.167.91
Dec 24 04:32:06 localhost sshd[3169]: Did not receive identification string from 201.234.178.62
Dec 23 06:08:44 localhost sshd[17418]: Address 221.204.245.144 maps to 144.245.204.221.adsl-pool.sx.cn, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!
Dec 23 06:08:47 localhost sshd[17420]: Address 221.204.245.144 maps to 144.245.204.221.adsl-pool.sx.cn, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!
Dec 24 06:13:31 localhost sshd[3180]: Did not receive identification string from 202.191.223.138
Dec 22 22:13:44 localhost sshd[17230]: Did not receive identification string from 133.242.167.91
Dec 22 08:13:05 localhost sshd[17018]: Invalid user zabbix from 83.170.63.40
Dec 22 06:38:43 localhost sshd[16889]: Invalid user share from 203.172.243.36
Dec 22 22:18:12 localhost sshd[17242]: Invalid user devtest from 133.242.167.91
2013-11-30 23:47:48,606 fail2ban.actions: WARNING [ssh] 221.12.12.3 already banned
2013-12-30 01:17:43,514 fail2ban.actions: WARNING [ssh] Ban 213.20.227.137
2013-12-30 02:17:43,613 fail2ban.actions: WARNING [ssh] Unban 213.20.227.137
"""

    print("Running through 'target'.......")

    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            target = f.read()
    else:
        target = t2

    n = 0
    for line in target.split('\n'):
        if line:
            n += 1
            print()
            print("Analysing line #%03d:\n%s" % (n, line, ))
            print("  Sortable date: %s." % (sortable_date(line), ))
            ip = list_of_IPs(line)
            info = get_log_info(line)
            print("      Information gleaned: %s"%(info, ) )

            if ip: # The following 'exercises' IP_info() """
                for addr in ip:
                    response = ip_info(addr) 
                    if response['err']:
                        print\
                        ("Attempt to retrieve demographics failed with '{0}'."\
                        .format(response['err']) )
                    else:
                        print("""    IP address is %(IP)s:
            Country/City: %(Country)s  %(City)s.
            Lat/Long: %(Lat)s/%(Lon)s""" % response) 

#   print("""    IP address is %(IP)s:
#       Country: %(Country)s;  City: %(City)s.
#       Lat/Long: %(Lat)s/%(Lon)s""" % ip_info("201.234.178.62"))

## [1]  SPoL  (Single Point of Light)
##      See: The Art of Unix Programming by Eric S. Raymond

    addrs = """
5.135.155.179
14.139.243.82
27.50.21.157
37.60.178.123
50.143.75.105
61.147.70.29
61.147.70.122
61.147.70.123
61.147.107.99
61.147.107.120
61.160.213.174
61.160.215.14
61.160.215.85
61.160.215.116
61.174.51.205
61.174.51.213
61.174.51.221
80.241.222.46
86.176.232.231
89.42.25.185
91.236.116.157
95.167.180.114
96.44.135.99
112.122.11.127
115.236.185.171
117.41.185.20
117.41.186.238
117.239.103.116
120.236.0.202
121.52.215.143
137.132.82.196
173.228.54.129
179.89.26.218
187.44.1.153
187.174.116.250
198.2.253.3
198.15.141.158
198.74.125.207
199.71.214.66
200.68.73.85
202.85.221.153
203.112.72.19
204.14.156.167
205.51.174.61
""".strip()
    addrs = addrs.split()

    for ip in addrs:
        print("  {0: >16}  converts to '{1}'.".format(ip, sortable_ip(ip) ) )

    # Exercise get_log_files(iterable_of_directories)...
    #params = ("/home/alex/Python/Parse/Logparse/", )
    params = ("Logs/", )
    log_files = get_log_files(params)
    for log_file in log_files:
        print(log_file)
