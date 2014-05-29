# ABOUT

Pydnsmap analyzes relations (mappings) between *queried FQDN* and *IP
addresses* hosting them for detecting malicious Internet activity. It uses DNS
data as input and produces as output (i) a list of suspicious mappings and (ii)
a graph of suspicious *communities* of FQDNs and IP addresses.

The definition of 'suspicious mapping' depends on the configuration of the
first analysis stage (see config.py). The definition of 'suspicious community'
depends on the analysis parameters set via the (simple) analysis GUI (see
dnsmapGUI.py).

# INSTALL

NOTE: these tools have been exclusively tested on Linux using Python 2.7.

The following python modules are required:
numpy, scipy, netaddr, python-levenshtein

Download the latest AsNum database (GeoIPAЅNum.dat) from
http://www.maxmind.com/en/asnum and save it to the /data directory. 

# RUNNING

1. Adapt config.py (see inline comments). 

By default, pydnsmap reads DNS data from a FIFO. Create a FIFO using 'mkfifo
my_fifo'. Then, write your data to this FIFO. Pydnsmap expects lines of text
following this format:

<UNIX timestamp> <Queried FQDN> <client ID> <IP address>

Note: the client ID is currently not used, just add arbitrary placeholder
instead.

2. Run 'python pydnsmap.py'. This should create a subdirectory (as specified in
config.py) where the following files are written: (i) a log file (by default,
it's called pydnsmap.log); (ii) a file called 'suspicious.txt', containing all
suspicious domain-ip mappings that were found; (iii) a file that contains the
final DNSMap in Python's pickle format. this is written just before the tool
terminates, unless this has been deactivated in config.py

3. Run 'python dnsmapGUI.py'. This allows you to load suspicious.txt, filter
the records therein, explore the resulting mapping graph, and export the final
list of malicious domains and IPs to a text file.

Note: the whitelist entries are regular expressions. Directly edit
whitelist.txt (or use the GUI) to modify the whitelist.

The results can be exported to a graph in GEXF format. Gephi (www.gephi.org) is
recommended for viewing/manipulating the graph.

