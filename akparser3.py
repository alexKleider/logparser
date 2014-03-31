#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :

# file: 'akparser3.py'
"""
A module to support parsing of log files.

* website?     # Perhaps some day.
* Repository: https://github.com/..  # Not pushed to github as of yet.
* Licensed under terms of GPL latest version.
* Copyright (c) 2014 Alex Kleider, alex@kleider.ca

The code used in this module was initially developed here:
~/Python/RegEx/logparse.py
It is expected that this module can eventually be a replacement
and logparse.py can be deleted.  Note that the API has changed
drastically.

I have tried several ways of implementing the ip_info() function.
See ip_json.py, xparse.py and ip_xml.py if interested.
In the end I decided that returning a dictionary (rather than a 
named tuple) would be best and that the easyest way to create such 
a dictionary would be using reg ex.

Parses log files:  To date, can handle:
        auth.log   and 
        fail2ban.log  .
Other logs can be added by request to author. (See (c) statement.)
#
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
        # Returns 'None' if line is not a recognized log entry.
    get_header_text(line_type)  
        # line_type: one of the strings provided in line_types.
        # Returns a string thus providing a mechanism for providing 
        # line_type specific information: this might be useful when 
        # presenting output.
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
"""

__all_ = ['list_of_IPs', 
          'ip_info',
          'line_types',
          'get_log_info',
          'get_header_text',
          'sortable_date'
          ]
__version__ = '0.1.0'
#
import re
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
re_format["invalid_user"] =\
    r"""Invalid user (?P<user>\S+) from """
header_text["invalid_user"] = "'auth.log' reporting 'invalid user's:"
re_format["no_id"] =\
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
#  SECTION which DEPENDS on 'line_types' CONTINUES...
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
    return header_text[line_type]

def get_log_info(line):
    """Returns 'None' if not a recognized log entry  or
    a tuple: line_type, data_gleaned.  The later is a list,
                         possibly empty, so far not more than one item.
    """
    for line_type in line_types:  # Assume a line can only be of 1 type.
        search_result = re_search4[line_type](line)
        if search_result:
            info_provided = keys_provided[line_type]
            if info_provided:  # Possibly empty list, unlikely >1 item.
                data_gleaned = []
                for item in info_provided:
                    data_gleaned.append(search_result.groups(item))
                return (line_type, data_gleaned, )
            else:
                return (line_type, ["-"], )
    return  # Redundant but makes the point that None is returned if
            # the line is not recognized as a known log line type.
#####################################################################

# To identify IP addresses (ipv4.)
ip_exp =\
r"""
\b
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
"""
list_of_IPs = re.compile(ip_exp, re.VERBOSE).findall
# list_of_Ips(line) returns a list (could be empty) of IP addresses.

#################################################################

# To get demographic info regarding an IP address:

url_format_str = \
"http://api.hostip.info/get_html.php?ip=%s&position=true"

encoding_exp = r"\bcharset=(?P<charset>\S+)"
get_encoding = re.compile(encoding_exp).search

info_exp = r"""
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
        """
get_IP_demographics = re.compile(info_exp, re.VERBOSE).search
#
def ip_info(ip_address):
    """
Returns a dictionary keyed by Country, City, Lat, Lon and IP.

Depends on http://api.hostip.info (which returns the following:
'Country: UNITED STATES (US)\nCity: Santa Rosa, CA\n\nLatitude:
38.4486\nLongitude: -122.701\nIP: 76.191.204.54\n'.)
THIS WILL BREAK IF THE WEB SITE CHANGES OR GOES AWAY!!!
"""
#   try:  # 16 lines in this try statement.
    # A file-like object is returned by the request:
    f_response =  urllib.request.urlopen(url_format_str %\
                                   (ip_address, ))
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
            "IP" : info.group("ip")            }
#   except:
    return {"Country" : "<request failed>",
            "City" : "<request failed>",
            "Lat" : "<failed>",
            "Lon" : "<failed>",
            "IP" : "<request failed>"         }
# End of IP demographics gathering section.

##################################################################

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
        currently can handle those of:
            auth.log 
            fail2ban. 
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
#

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
#
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
                print("""    IP address is %(IP)s:
        Country/City: %(Country)s  %(City)s.
        Lat/Long: %(Lat)s/%(Lon)s""" % response)

#   print("""    IP address is %(IP)s:
#       Country: %(Country)s;  City: %(City)s.
#       Lat/Long: %(Lat)s/%(Lon)s""" % ip_info("201.234.178.62"))

## [1]  SPoL  (Single Point of Light)
##      See: The Art of Unix Programming by Eric S. Raymond
