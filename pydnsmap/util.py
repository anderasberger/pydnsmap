# Copyright (c) 2014, FTW Forschungszentrum Telekommunikation Wien
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# * Neither the name of FTW nor the names of its contributors
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


from collections import defaultdict
import itertools
import logging
import re
import linecache

import netaddr

import GeoIP
geodb_ = GeoIP.open("data/GeoIPASNum.dat", GeoIP.GEOIP_MEMORY_CACHE)

def getTopDomainSuffix(domains, levels=2):
        d=defaultdict(int)
        for domain in domains:
            sdomain=domain.split('.')
            if len(sdomain)<levels:
                suffix=domain
            else:
                suffix='.'.join(sdomain[-levels:])
            d[suffix]+=1

        domainCounts=d.items()
        _,counts=zip(*domainCounts)
        domainCounts.sort(key=lambda x:x[1])

        return (domainCounts[-1][0], domainCounts[-1][1]/float(sum(counts)))

def splitOnCondition(seq, condition):
    """
    Splits a list of tuples (<x>,<y>) in two lists, depending on the condition
    on <y>. Returns the <x> elements as tuple of two lists.
    """
    l1,l2 = itertools.tee((condition(item),item) for item in seq)
    return ([i[0] for p, i in l1 if p], [i[0] for p, i in l2 if not p])

def minmax(data):
    """
    Computes the minimum and maximum values in one-pass using only
    1.5*len(data) comparisons
    """
    it = iter(data)
    try:
        lo = hi = next(it)
    except StopIteration:
        raise ValueError('minmax() arg is an empty sequence')
    for x, y in itertools.izip_longest(it, it, fillvalue=lo):
        if x > y:
            x, y = y, x
        if x < lo:
            lo = x
        if y > hi:
            hi = y
    return lo, hi

def dnameEquality(d1, d2):
    """
    returns an array of bools of length max(domain-levels(d1),
    domain-levels(d2)). The i-th element of the array is True if i-ld(d1) ==
    i-ld(d2), else it's False. d1 and d2 are aligned on the top level domain.
    """
    sd1 = d1.split('.')
    sd2 = d2.split('.')

    if not sd1 or not sd2:
        raise Exception('invalid domain names: '+d1+' '+d2)

    l_d1 = len(sd1)
    l_d2 = len(sd2)

    if d1 == d2:
        return [True]*l_d1
    else:
        min_l = min(l_d1, l_d2)
        matchmap = [False] * min_l
        for i in range(min_l):
            print sd1[-1-i], sd2[-1-i]
            if sd1[-1-i] == sd2[-1-i]:
                matchmap[-1-i] = True
        return matchmap

def getAsnAndOrganisation(ip):
    try:
        answer = geodb_.org_by_addr(str(ip))
    except GeoIP.error:
        return (None, None)
    else:
        if answer:
            if answer.startswith('AS'):
                try:
                    first_space = answer.index(' ')
                except ValueError:
                    asn = int(answer[2:])
                    return (asn, None)
                else:
                    asn = int(answer[2:first_space])
                    org = answer[first_space+1:]
                    return (asn, org)
            else:
                return (None, answer)
        else:
          return (None, None)

class SetGrab:
    """
    Return the object in a set that matches <value>.

    To be used as follows:

    s=set(['foobar', 'foo', 'bar'])
    g=SetGrab('foobar')
    if g in s:
        return g.actual_value

    http://python.6.n6.nabble.com/Get-item-from-set-td1530758.html
    """
    def __init__(self, value):
        self.search_value = value
    def __hash__(self):
        return hash(self.search_value)
    def __eq__(self, other):
        if self.search_value == other:
            self.actual_value = other
            return True
        return False

def punyDecodeDomain(dname):
    if 'xn--' in dname:
        try:
            return dname.decode('idna')
        except UnicodeError:
            """
            there's a python bug that causes the german 'scharfes s' not to be
            decoded correctly
            """
            logging.warn(u'IDNA decoding failed for '+unicode(dname))
            return dname
    else:
        return dname

def memory_usage():
    """Memory usage of the current process in kilobytes."""
    status = None
    result = {'peak': 0, 'rss': 0}
    try:
        # This will only work on systems with a /proc file system
        # (like Linux).
        status = open('/proc/self/status')
        for line in status:
            parts = line.split()
            key = parts[0][2:-1].lower()
            if key in result:
                result[key] = int(parts[1])
    finally:
        if status is not None:
            status.close()
    return result

def filterSingles(data):
    """
    """
    from collections import defaultdict
    domainToIPs = defaultdict(set)
    IPToDomains = defaultdict(set)

    for d in data:
        domainToIPs[d[1]].add(d[2])
        IPToDomains[d[2]].add(d[1])

    remainingDomains=set()

    for domain, IPs in domainToIPs.iteritems():

        if len(IPs)==1:
            ip=IPs.pop()
            if len(IPToDomains[ip])==1:
                continue
        remainingDomains.add(domain)

    numRemaining=len(set([d[1] for d in data if d[1] in remainingDomains]))
    print numRemaining, '/',len(domainToIPs),' domains left after removing singles'

    filteredData=[]
    for d in data:
        if d[1] in remainingDomains:
            filteredData.append(d)

    return filteredData

def filterSuspiciousData(data, minNumDomains=2, minNumIPs=2):
    """
    """
    from collections import defaultdict
    domainToIPs = defaultdict(set)
    IPToDomains = defaultdict(set)

    for d in data:
        domainToIPs[d[1]].add(d[2])
        IPToDomains[d[2]].add(d[1])

    remainingDomains=set()

    for domain, IPs in domainToIPs.iteritems():

        if len(IPs)<minNumIPs:
            continue

        for ip in IPs:
            """
            find the number of domains to which <ip> maps
            """
            numDomains = len(IPToDomains[ip])
            if numDomains>=minNumDomains:
                """
                This is an interesting domain-IP mapping, let's keep this domain
                """
                remainingDomains.add(domain)
                break

    numRemaining=len(set([d[1] for d in data if d[1] in remainingDomains]))
    print numRemaining, '/',len(domainToIPs),' domains left'

    filteredData=[]
    for d in data:
        if d[1] in remainingDomains:
            filteredData.append(d)

    return filteredData

def readSuspiciousFile(filename, lineNumStart=1, lineNumStop=0,
        omitNewIPs=False, filterExp=[], removeSingles=True):
    """
    expected format:
    timestamp fqdn IP None score <number of IPBlocks in which this fqdn
    appears> <number of fqdns in the IPBlock which contains this IP>
    """
    data=[]
    lineNum=lineNumStart

    if filterExp:
        filterHits=dict.fromkeys([regex.pattern for regex in filterExp], 0)
    else:
        filterHits=dict()

    print 'reading',filename,'from line',lineNumStart,'to line',lineNumStop
    linecache.updatecache(filename)

    while True:
        line=linecache.getline(filename, lineNum)

        if not line:
            # end of file
            break

        if lineNum>=lineNumStop:
            break

        lineNum+=1
        sl=line.split()
        try:
            if omitNewIPs and float(sl[4])==-1:
                continue

            dStr=sl[1]
            if dStr=='invalid_hostname':
                continue

#           if any(regex.match(dStr) for regex in filterExp):
#               #print 'whitelisted',dStr
#               filterHits+=1
#               continue

            for regex in filterExp:
                if regex.match(dStr):
                    filterHits[regex.pattern]+=1
                    break
            else:
                dUnicode=unicode(dStr, 'utf-8')
                if dStr==dUnicode:
                    data.append((int(sl[0]), dStr, str(netaddr.IPAddress(sl[2])),
                        sl[3], float(sl[4]), int(sl[5])))

        except (IndexError, ValueError):
            # may happen when reading incomplete files - ignore
            pass

    #print filterHits, 'filtered'
    if filterHits:
        print 'Filter hits:'
        for pattern, hits in filterHits.iteritems():
            print pattern,':',hits

    if removeSingles:
        cntPrevData=len(data)
        uniqueFqdns=set([fqdn for _,fqdn,_,_,_,_ in data])
        cntPrevUniqueFqdns=len(uniqueFqdns)
        #data=filterSuspiciousData(data, 1, 2)
        data=filterSingles(data)
        uniqueFqdns=set([fqdn for _,fqdn,_,_,_,_ in data])
        print 'removed',cntPrevData-len(data),'/',cntPrevData,'data records'
        print 'removed',cntPrevUniqueFqdns-len(uniqueFqdns),'/',cntPrevUniqueFqdns,'single FQDNs'

    return data

DOMAIN_COLOR='red'
IP_COLOR='blue'
CLIENT_IP_COLOR='green'
AS_COLOR='yellow'

def buildMappingGraph(data):
    import networkx as nx
    g=nx.Graph()

    if not data:
        return g

    _,domains,ips,clientIPs,_,_=zip(*data)

    for domain in domains:
        g.add_node(domain, color=DOMAIN_COLOR)

    for ip in ips:
        g.add_node(ip, color=IP_COLOR)

    for cip in clientIPs:
        if cip!='None':
            g.add_node(cip, color=CLIENT_IP_COLOR)

    for d in data:
        g.add_edge(d[1], d[2], {'score':d[4]})
        if d[3]!='None':
            g.add_edge(d[1], d[3])

    return g

#def compressGraph(g, clusteringThreshold=0.2, maxClustersPerComponent=1):
#    import networkx as nx
#    import DomainCluster as domclust
#    subgraphs = nx.connected_component_subgraphs(g)
#    numCompressed=0
#    dispersions=[]
#
#    for sg in subgraphs:
#        domains=[]
#        verbose=False
#        for node in sg.nodes_iter(data=True):
#            if node[1]['color']==DOMAIN_COLOR:
#                domains.append(domclust.DomainStr(node[0]))
#
#        #cl=domclust.domainCluster(domains, clusteringThreshold)
#        cl=domclust.domainClusterDBSCAN(domains, clusteringThreshold)
#        if verbose:
#            print cl
#        if len(cl)<=maxClustersPerComponent:
#            for ck, cv in cl.iteritems():
#                g.remove_nodes_from(cv.domains)
#                g.add_node(ck, color=DOMAIN_COLOR)
#                #FIXME: add external edges
#            numCompressed+=1
#            dispersions.append(domclust.clusterDispersion(domains))
#
#    print 'compressed',numCompressed,'out of',len(subgraphs),'subgraphs'
#    return dispersions

nodeDefaultSize_=10.0

def createASHierarchy(g, minIPsPerAS=2):
    """
    inserts hierarchical AS information in the graph. For each subgraph, the
    number ASes is evaluated. AS with more than <minIPsPerAS> IPs, an AS
    supernode is created that contains these IPs

    Modifies <g>, does not return anything!
    """
    from collections import defaultdict
    import numpy as np
    import networkx as nx
    subgraphs = nx.connected_component_subgraphs(g)

    for sgIndex, sg in enumerate(subgraphs):
        ASesPerSubgraph=defaultdict(list)
        for node in sg.nodes_iter(data=True):
            if 'color' in node[1] and node[1]['color']==IP_COLOR:
                ip=node[0]
                asNum, asOrg =getAsnAndOrganisation(ip)
                if asOrg:
                    try:
                        ASesPerSubgraph[unicode(asOrg, 'utf-8')].append(ip)
                    except UnicodeDecodeError:
                        """
                        this happens for some strange AS names, and causes
                        networkx's GEXF exporter to crash. fall back to using
                        the AS number.
                        """
                        ASesPerSubgraph[str(asNum)].append(ip)
                else:
                    ASesPerSubgraph['Unknown AS'].append(ip)

        for ASIndex, (asOrg,ips) in enumerate(ASesPerSubgraph.iteritems()):
            if len(ips)<minIPsPerAS:
                """
                Only one IP from this AS, don't collapse
                """
                continue
            else:
                newNodeId = 'SG'+str(sgIndex)+'_AS'+str(ASIndex)
                g.add_node(newNodeId, label=asOrg, color=AS_COLOR)
                """
                encode the color and size again in 'viz' format, else gephi
                cannot visualize it when exporting to GEXF
                """
                g.add_node(newNodeId,
                        {'viz':{
                            'color':{'r':'255','g':'255','b':'0'},
                            'size':str(nodeDefaultSize_+2*np.log(len(ips)))
                        }})
                for ip in ips:
                    g.add_node(ip, pid=newNodeId)

def getTimeRangeInFile(fname):
    """
    returns the time range in the suspicious file as a tuple (firstTimestamp,
    lastTimestamp)
    """
    from os.path import getsize

    def _getTimestamp(line):
        spl=line.split()
        return int(spl[0])

    linecache.updatecache(fname)
    with open(fname, 'r') as fh:
        firstLine = next(fh).decode()
        try:
            first=_getTimestamp(firstLine)
        except IndexError:
            return (None, None)

        last=None
        numBytesInFile = getsize(fname)
        seekTo=numBytesInFile
        while not last:

            # seek back 1024 bytes from the end of the file, hoping that we
            # would arrive somewhere before the start of the last line
            seekTo-=1024
            if seekTo < 0:
                # cannot seek over the start of the file
                seekTo = 0

            # seek relative to start of file
            fh.seek(seekTo)
            lines = fh.readlines()
            lastLine = lines[-1].decode()
            try:
                last=_getTimestamp(lastLine)
            except IndexError:
                if seekTo==0:
                    #nothing else we could do, give up
                    return (None, None)
        return (first, last)
    return (None, None)

def seekToTimestamp(fn, timestamp, matchFirstOccurrence=True):

    def _getTimestamp(line):
        spl=line.split()
        return int(spl[0])

    def _fileLen(fname):
        """
        find number of lines in file
        """
        with open(fname) as f:
            for i, l in enumerate(f):
                pass
            return i + 1
        return 0

    fLen=_fileLen(fn)

    def _slowSeek(fPos, fn, searchedTimestamp, matchFirstOccurrence):
        searchForward=False
        searchBackward=False
        while True:
            if fPos<0:
                fPos=0
                break

            if fPos>fLen:
                fPos=fLen+1
                break

            line = linecache.getline(fn, fPos)
            t=_getTimestamp(line)
            if t<searchedTimestamp:
                if searchBackward:
                    fPos-=1
                    break
                searchForward=True
                fPos+=1
            elif t>searchedTimestamp:
                if searchForward:
                    fPos+=1
                    break
                searchBackward=True
                fPos-=1
            else:
                break

        while True:
            # this assumes that we are already in a block of identical timestamps
            if matchFirstOccurrence:
                # search backward
                if fPos==1:
                    return fPos
                lastfPos=fPos
                fPos-=1
            else:
                # search forward
                if fPos==fLen:
                    return fPos
                lastfPos=fPos
                fPos+=1
            line = linecache.getline(fn, fPos)
            t=_getTimestamp(line)
            if t!=searchedTimestamp:
                return lastfPos

    fPos=1
    delta=fLen/2

    while True:

        if fPos<0: return 1
        #if fPos>fLen: return fLen+1
        if fPos>fLen: fPos=fLen+1

        line = linecache.getline(fn, fPos)

        try:
            t=_getTimestamp(line)
        except IndexError:
            if fPos==1:
                """
                seems that even the first line is not complete
                """
                return fPos
            else:
                """
                seems we encountered an incomplete line, let's try the previous
                one
                """
                fPos-=1
                continue
        else:
            if t==timestamp or delta==1:
                break
            else:
                if t<timestamp:
                    fPos+=delta
                elif t>timestamp:
                    fPos-=delta
                delta/=2

    print 'FOOO',fPos,matchFirstOccurrence,timestamp

    if matchFirstOccurrence and fPos==1:
        return fPos
    elif not matchFirstOccurrence and fPos==(fLen+1):
        return fPos
    else:
        return _slowSeek(fPos, fn, timestamp, matchFirstOccurrence)
