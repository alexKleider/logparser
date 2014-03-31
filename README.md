###logparser3.py
This utility was inspired by the need to harden a **Raspberry Pi**
co-located with **pcextreme.nl** in the Netherlands.  Right from the get-go
it was being constantly attacked.  Analysis of the logs (_auth.log_ is the
most useful) suggested that certain IP addresses should be blocked
outright and since there are many, using _ipset_ with _iptables_ seems the
best solution.

Some attackers make thousands of attempts creating very large log files.
Hence the incentive to automate log file analysis and provide output
in a form easily used with _ipset_. 

_logparse.py3_ and _akparser3.py_, a local dependency, are heavily
documented inside _usage_ statements within the code.  Also included 
(with it's own licensing) is _docopt.py_, an extremely useful third party 
module invaluable for setting up a usage statement and capturing command 
line arguments, from an **SPoL** (Single Point of Light- Described by 
Eric Raymond in [**The Art of Unix Programming**](http://www.amazon.com/Programming-Addison-Wesley-Professional-Computng-Series/dp/0131429019).)

The input side seems to be working satisfactorily but so far, the only
output is test code to check that the input has been captured correctly. 
Code to present the data in keeping with specified command line options
has yet to be written.  In other words, this is still a work in
progress.  Comments, suggestions and even just plain criticisms
welcomed. (alex at kleider dot ca)
