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
Other logs can be added by request to author.

Usage: 
    import akparser3
    ...
    Provides the following:  i.e. Here is the API.

    IpDemographics
        A class, which provides the following:
    IpDemographics.ip_info(ip_address)
        Returns   a dictionary keyed by
            'encoding', 'err', 'IP',
            'Country', 'Region', 'City', 'Lat', 'Lon',
            'ISP', 'OrgName'
    LIST_OF_IPS(line)
        An re.compile(..).findall function
        Returns a list.  (i.e. Allows input to contain >1 IP/line.)
        Generally log files report only one IP per line unless a 
        reverse look up is provided in which case the second one
        is the same IP but with the dotted quads in reverse order.
    LINE_TYPES : a list of strings. Provides our SPoT (or DRY.)
    get_log_info(line)
        Returns a tuple: line_type, data_gleaned.  
            line_type: one of the strings provided in LINE_TYPES .
            data_gleaned: a list, possibly empty.
                 Currently there is never >1 item in the list.
        Returns None if line is not a recognized log entry.
    get_header_text(line_type)  
        line_type: one of the strings provided in LINE_TYPES .
        Returns a string thus providing a mechanism for providing 
        line_type specific information: this might be useful when 
        presenting output.
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

__all__ = ['LIST_OF_IPS', 
          'IpDemographics',
          'LINE_TYPES ',
          'get_log_info',
          'get_header_text',
          'get_log_files',
          'sortable_date',
          'sortable_ip'
          ]
__version__ = '0.2.6'

import re
import os
import urllib.request
import datetime

LINE_TYPES  = ['invalid_user',   'no_id',     'break_in', 
              'pub_key',        'closed',    'disconnect', 
              'listening',      'ban',       'unban', 
              'already_banned'                            ]
# BEGINNING of SECTION which DEPENDS on LINE_TYPES 
# and therefore will have to be modified if any 
# changes are made to LINE_TYPES .
RE_FORMAT = {}         # } All keyed
RE_SEARCH4 = {}        # } by items
KEYS_PROVIDED = {}     # } found in
HEADER_TEXT = {}       # } 'LINE_TYPES '.

# Expressions relevant to auth.log:
RE_FORMAT["invalid_user"] = \
    r"""Invalid user (?P<user>\S+) from """
HEADER_TEXT["invalid_user"] = "'auth.log' reporting 'invalid user's:"
RE_FORMAT["no_id"] = \
    r"""Did not receive identification string from \S+"""
HEADER_TEXT["no_id"] = "'auth.log' reporting 'no id's:"
RE_FORMAT["break_in"] = r"POSSIBLE BREAK-IN ATTEMPT!"
HEADER_TEXT["break_in"] = \
    "'auth.log' reporting 'POSSIBLE BREAK-IN ATTEMPT!'s:"
RE_FORMAT["pub_key"] = r""" Accepted publickey for (?P<user>\S+)"""
HEADER_TEXT["pub_key"] = "'auth.log' reporting ''s:"
RE_FORMAT["closed"] = r""" Connection closed by \S+"""
HEADER_TEXT["closed"] = "'auth.log' reporting 'closed's:"
RE_FORMAT["disconnect"] = r""" Received disconnect from (?P<who>[.\w+]):"""
HEADER_TEXT["disconnect"] = \
    "'auth.log' reporting 'Received disconnect from's:"
RE_FORMAT["listening"] = r""" Server listening on (?P<listener>.+)"""
HEADER_TEXT["listening"] = "'auth.log' reporting 'Server listening on's:"

# fail2ban.log lines:
RE_FORMAT["ban"] = \
    r"fail2ban\.actions: WARNING \[ssh\] Ban "
HEADER_TEXT["ban"] = "'fail2ban' reporting 'ban's:"
RE_FORMAT["unban"] = \
    r"fail2ban\.actions: WARNING \[ssh\] Unban "
HEADER_TEXT["unban"] = "'fail2ban' reporting 'unban's:"
RE_FORMAT["already_banned"] = r" already banned$"
HEADER_TEXT["already_banned"] = "'fail2ban' reporting 'already banned's:"
# SECTION which DEPENDS on 'LINE_TYPES ' CONTINUES...
for key in LINE_TYPES :
    RE_SEARCH4[key] = re.compile(RE_FORMAT[key]).search

KEYS_PROVIDED["invalid_user"] = ["user"]
KEYS_PROVIDED["no_id"] = []
KEYS_PROVIDED["break_in"] = []
KEYS_PROVIDED["pub_key"] = ["user"]
KEYS_PROVIDED["closed"] = []
KEYS_PROVIDED["disconnect"] = ["who"]
KEYS_PROVIDED["listening"] = ["listener"]

KEYS_PROVIDED["ban"] = []
KEYS_PROVIDED["unban"] = []
KEYS_PROVIDED["already_banned"] = []
# END of SECTION which DEPENDS on 'LINE_TYPES '.

def get_header_text(line_type):
    """Return header text appropriate to line type."""
    return HEADER_TEXT[line_type]

def get_log_info(line):
    """Returns 'None' if not a recognized log entry  or
    a tuple: line_type, data_gleaned.  The later is a list if
    there is data gleaned, None if not.
    """
    for line_type in LINE_TYPES :  # Assume a line can only be of 1 type.
        search_result = RE_SEARCH4[line_type](line)
        if search_result:
            data_gleaned = []
            info_provided = KEYS_PROVIDED[line_type]
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
IP_EXP = \
r"""
\b
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
"""
LIST_OF_IPS = re.compile(IP_EXP, re.VERBOSE).findall
# list_of_Ips(line) returns a list (could be empty) of IP addresses.

#################################################################
# To get demographic info regarding an IP address:

class IpDemographics(object):

    """A class to facilitate being able to easily switch from using one url
    for IP demographic information, to another. An instance can be used to
    gain its ip_info method which takes an IP address and returns
    information about it (if available) and any error message if present.
    The encoding used by the web site is also reported (with utf-8 as the
    default.)
    A default URL (index to) is set but can be over-ridden by an integer
    parameter when initializing.
    """

    default_url = 1

    default_encoding = "utf-8"
    charset_re = r"""\bcharset="(?P<encoding>[-\w]+)"""
    get_encoding = re.compile(charset_re).search

    urls = ("hostip",
            "addgadgets",
            )

    url_dic = {\
        urls[0] : \
            "http://api.hostip.info/get_html.php?ip={0}&position=true",
        urls[1] : \
            "http://addgadgets.com/ipaddress/index.php?ipaddr={0}"
        }

#url_format_str = \
#"http://api.hostip.info/get_html.php?ip={0}&position=true"

    info_re_dic = {\
        urls[0] : r"""
            Country:[ ](?P<country>.*) [\n]
            City:[ ](?P<city>.*) [\n] [\n]
            Latitude:[ ](?P<lat>.*) [\n]
            Longitude:[ ](?P<lon>.*) [\n]
            IP:[ ](?P<ip>.*)
            """                ,
        urls[1] : r"""
            \bcharset="(?P<encoding>[-\w]+)" .+?
            (?P<IP>[0-9]{1,3}(?:[.][0-9]{1,3}){3}) .+?
            Country:&nbsp;</td><td> (?P<Country>[ \w]+) .+?
            Region:&nbsp;</td><td> (?P<Region>[ \w]+) .+?
            City:&nbsp;</td><td> (?P<City>[ \w]+) .+?
            Latitude:&nbsp;</td><td> (?P<Lat>[-]?[.\d]+) .+?
            Longitude:&nbsp;</td><td> (?P<Lon>[-]?[.\d]+) .+?
            ISP[ ]name:&nbsp;</td><td> (?P<ISP>[ .\w]+) .+?
            Organization[ ]name:&nbsp;</td><td> (?P<OrgName>[ .\w]+)
            """ }

    get_demographics_dic = {\
        urls[0] : re.compile(info_re_dic[urls[0]],
                            re.VERBOSE + re.DOTALL),
        urls[1] : re.compile(info_re_dic[urls[1]],
                            re.VERBOSE + re.DOTALL)
                            }
    demo_keys = ('encoding', 'err', 'IP',
        'Country', 'Region', 'City', 'Lat', 'Lon',
        'ISP', 'OrgName', )



    def __init__(self, url=default_url):

        self.url_template = IpDemographics.url_dic[\
                                        IpDemographics.urls[url]]
        self.demographics_pattern = re.compile(\
            IpDemographics.info_re_dic[IpDemographics.urls[url]],
            re.VERBOSE + re.DOTALL)

    def ip_info(self, ip_address):
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
        ret = {}
        for key in IpDemographics.demo_keys:
            ret[key] = ""
        try:  
            url_response = urllib.request.urlopen(\
                self.url_template.format(ip_address))
        except urllib.request.URLError as err_report: 
            ret['err'] = err_report
            return ret

        ip_demographics = url_response.read()  # The returned Data.
        data  = ip_demographics.decode(\
            IpDemographics.default_encoding, "backslashreplace.")
        encoding = \
            IpDemographics.get_encoding(data).group('encoding')
        if not encoding:
            encoding = IpDemographics.default_encoding
        if encoding != IpDemographics.default_encoding:
            data  = ip_demographics.decode(\
                                    encoding, "backslashreplace.")
        info = self.demographics_pattern.search(data)
        if info:
            for key in IpDemographics.demo_keys:
                try:
                    ret[key] = info.group(key)
                except IndexError:
                    pass
        return ret
# End of IP demographics gathering section.

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

THISYEAR = datetime.date.today().year
THISMONTH = datetime.date.today().month

def _sample_yr(samplemonth):
    """ auth.log provides date without the year 
        so we have to "guess."  """
    tmonth = THISMONTH
    while tmonth > 0:
        if samplemonth == tmonth:
            return THISYEAR
        tmonth -= 1
    return THISYEAR -1


MONTHS = {"Jan" : 1, "Feb" : 2, "Mar" : 3, "Apr" : 4,
          "May" : 5, "Jun" : 6, "Jul" : 7, "Aug" : 8,
          "Sep" : 9, "Oct" : 10, "Nov" : 11, "Dec" : 12  }

def sortable_date(log_line):
    """ Needs to handle all types of log lines. 
        Currently can handle those of: auth.log fail2ban. 
        Returns None if parsing is unsuccessful."""
    try:   # auth.log 
        l = log_line[:15].split()
        return  "%s-%02d-%02d %s" % \
            (_sample_yr(int(MONTHS[l[0]])), 
            MONTHS[l[0]], 
            int(l[1]), l[2], )
    except:   # TypeError or IndexError
        pass  # I want ANY error to pass
    try:  # fail2ban.log
        l = log_line[:10].split('-')
        return "%s-%s-%s %s" % \
            (l[0], l[1], l[2], log_line[11:19], )
    except:  # Ditto, this might deserve further discussion.
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
        for dir_name, _, file_list in os.walk(directory):
            for file_name in file_list:
                if '.log' in file_name:
                    d_n = dir_name
                    while d_n[-1:] == '/':  # To eliminate double slashes.
                        d_n = d_n[0:-1]
                    log_files.append('{0}/{1}'.format(d_n, file_name))

                    #print("Directory '{0}':".format(item[0]))
                    #print("\t{0}".format(l1))
    return log_files

def main():
    """ Testing code. """

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

    demo_getter = IpDemographics(1)
    n = 0
    for line in target.split('\n'):
        if line:
            n += 1
            print()
            print("Analysing line #%03d:\n%s" % (n, line, ))
            print("  Sortable date: %s." % (sortable_date(line), ))
            ip = LIST_OF_IPS(line)
            ###############
            info = get_log_info(line)
            print("      Information gleaned: %s"%(info, ) )

            if ip: # The following 'exercises' IP_info() """
                for addr in ip:
                    response = demo_getter.ip_info(addr) 
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



if __name__ == "__main__":
    main()
