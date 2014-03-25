#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :

# file: 'akparser3.py'
"""
A module to support parsing of log files.

"""

import re

# To identify IP addresses (ipv4.)
ip_exp =\
r"""
\b
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
"""
list_of_IPs = re.compile(ip_exp, re.VERBOSE).findall
# returns a list: logparse:list_of_IPs


if __name__=="__main__":
    print("Running Python3 script: 'akparser3.py'.......")


