# Copyright (c) 2014, FTW Forschungszentrum Telekommunikation Wien
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# # Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# # Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# # Neither the name of FTW nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL FTW
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE

import os
import time
import logging
from dnsmapIO import (INPUTMODE_FIFO, INPUTMODE_PROTOBUF, INPUTMODE_PCAP_FILE,
    INPUTMODE_PCAP_IF)

# FIXME, debug only
#import faulthandler
#faulthandler.enable()

"""
create working directory
"""
workingDir='pydnsmap_'+str(time.time())
os.mkdir(workingDir)
workingDir=os.path.abspath(workingDir)

"""
setup logging
"""
logformat='%(asctime)s %(levelname)-8s %(message)s'
logdateformat='%m-%d %H:%M'
logging.basicConfig(filename=os.path.join(workingDir, 'pydnsmap.log'),
        filemode='w', format=logformat, datefmt=logdateformat,
        level=logging.INFO)

"""
the input source: can be either a file, or a network interface (e.g., eth0);
depends on the inputMode, see below
"""
#inputSource='/path/to/file.txt'
#inputSource='/path/to/file.gz'
inputSource='fifo'

"""
the input mode to be used.
INPUTMODE_FIFO: read from text input
INPUTMODE_PCAP_FILE: read from PCAP file
INPUTMODE_PCAP_IF: read from PCAP network interface
"""
inputMode=INPUTMODE_FIFO

"""
boolean flag, indicates if inputSource contains gzipped input or not
"""
#gzippedInput=True
gzippedInput=False

"""
file to write resulting DNSMap to. If set to None, the DNSMap doesn't get saved
at the end
"""
outfilename=os.path.join(workingDir, 'dnsmap.txt')

"""
load a previously dumped DNSMap from a file, for initialization before starting
to process the data
"""
dnsmapToLoad=None

"""
dump the processed DNS mappings to a SQLite database file
"""
dbfile=None
#dbfile=os.path.join(workingDir, 'output.db')

"""
the clusteringThreshold defines the required minimum distance between two
domains to be considered similar. 0.0=identical, 1.0=completely different.
"""
clusteringThreshold=0.35

"""
the domainCountThreshold defines the share of clusters of two IPBlocks that
need to be similar (wrt. to the domain distance and the clusteringThreshold),
so that these blocks can be merged. 0.0=deactivated, 1.0=all clusters must have
a similar counterpart in the other IPBlock.
"""
domainCountThreshold=0.5

"""
maximum number of domains in a cluster. if the cluster exceeds this number, it
will get 'collapsed', i.e. the contents of the cluster will be dropped and only
the cluster's representative will be kept. from then on, no more domains will
be stored in this cluster.
"""
maxClusterSize=30

"""
the maximum number of clusters per IPBlock. if this number is exceeded, the
IPBlock will not create any more clusters, and mappings that do not match will
be silently ignored
"""
maxNumClusters=50

"""
a time interval in seconds. at the end of each interval, the tool merges
adjacent, similar IPBlocks
"""
timebinSizeMerge=3600*6

"""
a time interval in seconds. at the end of each interval, the tool first splits
blocks that do not fulfill the merge condition anymore, and then flushes
domain names and IPBlocks that have not been used in this interval. the tool
starts to output suspicious mappings after the first cleanup operation.
"""
timebinSizeSplitAndCleanup=3600*24*2

"""
a time interval in seconds. within this time interval, each domain-to-IP
mapping is forwarded only once to the DNSMap, all other occurrences of this
mapping are ignored.
"""
filterTimeThreshold=3600*3
#filterTimeThreshold=0

