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


import random
import logging
from collections import defaultdict
import numpy as np
from scipy.cluster.vq import kmeans2,vq
import Levenshtein as lev
import TldMatcher as tldm
from util import minmax,splitOnCondition,SetGrab,punyDecodeDomain

tldmatcher_ = tldm.TldMatcher()

class DomainStr(unicode):
    """
    This class stores domain names. It extends the unicode class by the
    following attributes/methods:

    - rSplitIndexes(): the reversed list of domain levels, split on the separating
      dots
    - weight: the weight of this domain, a positive integer
    - ipblocks: the set of IPBlock instances to which the domain belongs
    """

    __slots__=['rSplitIndexes', 'ipblocks']

    def __new__(self, string):
        """
        Parameters:
        string: either a string containing the domain name or a list of strings
        containing the REVERSED domain name
        """

        if isinstance(string, list):
            """
            this domain name is already split. this is usually because it is
            representing a median.
            """
            alreadySplit=True
            s = '.'.join(string)
            domain=super(DomainStr, self).__new__(self, s)
        else:
            alreadySplit=False
            string = punyDecodeDomain(string)
            domain=super(DomainStr, self).__new__(self, string)

        """
        unicode did it's magic, for sure <domain> is now in unicode format, no
        matter in which format <string> was
        """

        if alreadySplit:
            splitView=string
        else:
            tld = tldmatcher_.getTld(domain)

            if tld:
                shortDomain = domain[:-len(tld)-1]
                if shortDomain:
                    splitView = shortDomain.split('.') + [tld]
                else:
                    """
                    the entire domain (e.g. mail.nhs.uk) is a TLD
                    """
                    splitView = [tld]
            else:
                splitView = domain.split('.')

        splitIndexes=[]
        curSplitIndex=0
        for splitLevel in splitView:
            l=len(splitLevel)
            splitIndexes.append((curSplitIndex, curSplitIndex+l))
            curSplitIndex+=(l+1) # take into account the dot
        splitIndexes.reverse()
        domain.rSplitIndexes = tuple(splitIndexes)

        domain.ipblocks = set()
        return domain

    def addIPBlock(self, ipb):
        self.ipblocks.add(ipb)

    def removeIPBlock(self, ipb, warn=True):
        try:
            self.ipblocks.remove(ipb)
        except KeyError:
            if warn:
                msg = (u'IPBlock'+unicode(ipb)+u' not found in '
                        'DomainStr '+unicode(self)+u' with '
                        'IPBlocks '+unicode(self.ipblocks))
                logging.warn(msg)

    def rSplitView(self):
        return [self[i:j] for i, j in self.rSplitIndexes]

    def numDomainLevels(self):
        return len(self.rSplitIndexes)

    def __add__(self, y):
        """
        adding to DomainStr is not wanted and therefore not supported
        """
        raise RuntimeError

class DomainStrFactory():

    __slots__=['domains']

    def __init__(self):
        self.domains = set()

    def makeDomainStr(self, dname):
        domainstr = self.getDomainStr(dname)
        if not domainstr:
            domainstr = DomainStr(dname)
            self.domains.add(domainstr)
        return domainstr

    def getDomainStr(self, dname):
        g = SetGrab(dname)
        if g in self.domains:
            return g.actual_value
        else:
            return None

    def flushEmptyDomains(self):
        emptyDomains = [d for d in self.domains if not d.ipblocks]
        for d in emptyDomains:
            self.domains.remove(d)

class DomainCluster():
    """
    This class is a container for sets of domains that share a certain
    property.
    """

    __slots__=['domains', 'isCollapsed', 'activeIPs']

    def __init__(self, domains, isCollapsed=False):
        """
        domain: a single <DomainStr> or a list of <DomainStr> objects to be
        added to the cluster
        isCollapsed: boolean flag to remember if we want to store the actual
        domains we added to this cluster
        """
        self.domains = set()
        if isinstance(domains, DomainStr):
            domains=[domains]
        self.isCollapsed = False
        self.multiAdd(domains)
        self.activeIPs = None

        """
        if this cluster is collapsed, we set this only here (AFTER adding the
        domains), so that the <domains> that were used for creating this
        cluster are being stored in any case
        """
        self.isCollapsed = isCollapsed

    def add(self, domain):
        """
        Add a single <DomainStr> object to this cluster.
        """
        self.domains.add(domain)

    def multiAdd(self, domains):
        """
        Add multiple <DomainStr> objects to this cluster.
        """
        for d in domains:
            self.add(d)

    def delete(self, domain):
        """
        Remove a domain from this cluster
        """
        try:
            self.domains.remove(domain)
            return True
        except KeyError:
            return False

    def flushDomains(self):
        """
        Removes all domains from this clusters
        """
        self.domains.clear()

    def setAllDomainsActive(self):
        for d in self.domains:
            d.isActive=True

    def setAllDomainsActive(self):
        for d in self.domains:
            d.isActive=True

    def initActiveIPs(self, numIPs):
        self.activeIPs = np.array([False]*numIPs, dtype=np.bool)

    def setIpActive(self, ipIndex):
        try:
            self.activeIPs[ipIndex]=True
        except IndexError:
            logging.error('cluster ' + str(self) + ' does not contain IP'
                    ' with index '+str(ipIndex))

    def setAllIPsActive(self, numIPs):
        self.activeIPs = np.array(np.ones(len(self.activeIPs)),
                dtype=np.bool)

    def setAllIPsInactive(self):
        self.activeIPs = np.array(np.zeros(len(self.activeIPs)),
                dtype=np.bool)

    def __str__(self):
        if self.isCollapsed:
            s=u'*'
        else:
            s=u''
        return s+unicode([unicode(d) for d in self.domains])

    def __len__(self):
        return len(self.domains)

    def __repr__(self):
        return unicode([unicode(d) for d in self.domains])

    def __contains__(self, x):
        return (x in self.domains)

def domainDist(domObj1, domObj2):
    """
    Compute the distance between two domains.
    """

    if domObj1==domObj2:
        return 0.0

# FIXME, debugging
    if isinstance(domObj1, tuple) or isinstance(domObj2, tuple):
        msg=unicode(domObj1)
        msg=msg.encode('utf-8')
        logging.error(msg)
        msg=unicode(domObj2)
        msg=msg.encode('utf-8')
        logging.error(msg)

    sx=domObj1.rSplitView()
    sy=domObj2.rSplitView()

    mn,mx=minmax((domObj1.numDomainLevels(), domObj2.numDomainLevels()))

    dist=0.0

    """
    """
    totWeight=0

    """
    we consider the ratio of identical domain levels for the distance.
    the  eight of each identical domain level is computed as
    1/(offset+domainLevel), where domainLevel=0 is the top level domain. I.e.,
    the less significant a domain level is, the less weight it gets. <offset>
    is used to control the decline rate of the weight from one level to the
    next.
    """

    # FIXME, hardcoded parameter; needs to be FLOAT, else the divisions below
    # give integers!
    offset=3.0
    tldPenalty=0.0

    """
    First, compare all domain levels which exist in both domains, starting from
    the top-level-domain
    """
    for dLevel, (curSx, curSy) in enumerate(zip(sx[:mn], sy[:mn])):

        if dLevel==0:
            """
            this is the TLD: weight both the top level domain and the second
            level domain with maximum weight
            """
            #pWeight=1/offset
            if curSx != curSy:
                # TLDs are different
                #dist+=pWeight
                tldPenalty=0.05
            #totWeight+=pWeight
        else:
            """
            weight both the top level domain and the second level domain with
            maximum weight
            """
            pWeight=(1/(offset+dLevel-1))

            """
            the weight of this partial distance corresponds to the length of the
            longer partial string
            """
            lWeight=max(len(curSx), len(curSy))

            weight=lWeight*pWeight
            #print 'pweight',pWeight
            #print 'lweight',lWeight
            #print 'weight',weight

            if curSx != curSy:
                dd=(1-lev.ratio(curSx,curSy))*weight
                #print 'level',dLevel
                #print 'dd',dd
                dist+=dd
                #print 'dist',dist

            totWeight+=weight

    """
    Second, consider also the domain levels that exist only in one of the two
    domains
    """
    if mn!=mx:
        lx=domObj1.numDomainLevels()
        ly=domObj2.numDomainLevels()
        if lx<ly: longer = sy
        else: longer = sx

        """
        if one domain has more levels than the other, we need to consider
        these additional letter insertions. the number of insertions is
        simply the length of the longer substring (without dots)
        """
        for dLevel, j in enumerate(longer[mn:], start=mn):
            lWeight=len(j)
            pWeight=1/(offset+dLevel)
            weight=lWeight*pWeight
            dist+=weight
            totWeight+=weight

    #print 'dist',dist
    #print 'weight',weight

    if totWeight:
        dist=dist/totWeight+tldPenalty
    else:
        try:
            logging.warn('strange fqdns: '+str(domObj1)+', '+str(domObj2))
        except UnicodeEncodeError:
            pass
        dist=tldPenalty

    dist=min(dist,1.0)

    return dist

def _getLD(data, level):
    """
    This function returns for a set of domain names in <data> a list of tuples
    (domain-level, occurrences), where domain-level is the <i>-th domain level
    of a domain (counted from the end, so the TLD is level one), and
    occurrences is the total number of occurrences of this string at this level
    across all domains in data. This also considers the weight of a domain,
    e.g. a domain with weight=2 contributes to the number of occurrences with
    two.

    data: a tuple with (split domains, weights)
    level: a positive integer
    """
    domainLevels=defaultdict(int)
    for d,w in data:
        try:
            ld=d[level]
        except IndexError:
            ld=u''
        domainLevels[ld]+=w
    return domainLevels.items()

def domainMedian(domainObjs, numSamples=200):
    """
    Compute the median Domain object from a list of Domain objects. The median
    is defined as the string that is computed from the per-domain-level
    Levenshtein string medians.

    if <numSamples> is set to a value > 0, this number of samples will be
    picked randomly from <domainObjs>, and the median is then computed from
    this set.

    returns a Domain object
    """
    if numSamples and len(domainObjs)>numSamples:
        domainObjs=list(random.sample(domainObjs, numSamples))

    data=[(d.rSplitView(), 1) for d in domainObjs]
    mxIdx=max([len(d) for d,_ in data])
    medianParts=[]

    for i in range(mxIdx):
        occurrencesWithWeights = _getLD(data, i)
        domainLevels,levelWeights = zip(*occurrencesWithWeights)
        try:
            ldMedian = lev.median(domainLevels, levelWeights)
        except TypeError:
            logging.error('median error: '+str(domainLevels))
        else:
            if ldMedian:
                """
                ignore empty medians; prepend this level to output
                """
                medianParts.insert(0, ldMedian)

    """
    we construct the final median now directly from the constructed parts, i.e.
    we don't let the DomainStr constructor split it in parts which might be
    different from the parts we found here, and would therefore impair the
    alignment for comparisons later.
    """
    medianObj = DomainStr(medianParts)
    return medianObj

def _twoMedians(domainDists):
    """
    Runs k-means with k=2 to find two clusters with similar distance values.
    The input parameter <domainDists> contains tuples (<domainname>,
    <distance>).

    returns the two clusters as a tuple of two lists, where each list contains
    the <DomainStr> objects in the cluster
    """
    dists,domains = zip(*domainDists)
    #_,labels = kmeans2(np.array(dists), 2, minit='points')
    mn,mx = minmax(domainDists)
    _,labels = kmeans2(np.array(dists), np.array([mn[0], mx[0]]), minit='matrix')
    labeledDomains = zip(domains, labels)
    d1,d2 = splitOnCondition(labeledDomains, lambda x:x[1]==0)
    return (d1,d2)

def domainCluster(domains, clusteringThreshold):
    """
    Clusters <domains> such that no domain has a distance more than
    <clusteringThreshold> to the cluster's center.

    1. find median of domains + compute distances between all domains and the
    median
    2. find all domains that have a distance to the median of less-equal-than
    <clusteringThreshold> -> this domains form a cluster now and are removed
    from all further processing
    3. for all the others, continue from 1.

    NOTE: it might happen at step 2. that *no* domain is close enough to the
    median. In this case, we find two sets of domains with similar distances to
    the computed median using kmeans, and continue for each of them separately
    from 1. In case we cannot further cluster the domains by that procedure, we
    assign all remaining domain to separate clusters that contain only one
    domain each.

    domains: a list of <DomainStr> objects
    clusteringThreshold: a float between 0 and 1

    returns a dict with cluster centers as keys and WeakSets containing
    references to elements of <domains> as values
    """
    clusters = dict()

    def _clusterAdd(key, values):
        """
        Utility function that adds domains (aka <values>) to a cluster. If the
        cluster identified by <key> doesn't yet exist, it is created.
        """
        try:
            existingValues = clusters[key]
        except KeyError:
            # cluster doesn't yet exist, let's create it
            clusters[key] = DomainCluster(values)
        else:
            existingValues.multiAdd(values)

    def _recursiveClustering(domains, th):
        if not len(domains):
            return
        elif len(domains) == 1:
            d = list(domains)[0]
            _clusterAdd(DomainStr(d), set([d]))
        else:
            clusterCenter = domainMedian(domains)

            # FIXME, do we really need this?
            if not clusterCenter:
                return

            good = set()
            bad = set()
            badDists = []
            for d in domains:
                dist = domainDist(d, clusterCenter)
                if dist<=th:
                    good.add(d)
                else:
                    bad.add(d)
                    badDists.append((dist, d))

            if good:
                if bad:

                    """
                    The 'good' are close to the median of *all* domains, but not
                    necessarily close enough to the median of the good
                    """
                    _recursiveClustering(good, th)

                    if len(bad) == 1:
                        """
                        there's only one unclustered domain left, let's give it
                        it's own cluster
                        """
                        _clusterAdd(domainMedian(bad), bad)
                    else:
                        """
                        we have some unclustered left, let's see if we can
                        find clusters for them
                        """
                        _recursiveClustering(bad, th)
                else:
                    """
                    Only good ones are left, let's make them a cluster
                    """
                    _clusterAdd(clusterCenter, good)

                return
            else:
                """
                we were not able to find a suitable cluster even for a single
                domain in this iteration. let's try to find to separate
                clusters using k-Means and continue with them
                """
                bad1, bad2 = _twoMedians(badDists)

                if ((not bad1 and bad2==domains) or (not bad2 and
                        bad1==domains)):
                    """
                    this didn't help, we're stuck. let's give each of these
                    domains it's own cluster
                    """
                    for d in bad:
                        _clusterAdd(DomainStr(d), set([d]))
                else:
                    """
                    we got two new clusters, let's try again separately
                    """
                    _recursiveClustering(bad1, th)
                    _recursiveClustering(bad2, th)
                return

    _recursiveClustering(domains, clusteringThreshold)
    return clusters
