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


import logging
import numpy as np
from netaddr import IPRange
from netaddr.ip import IPAddress
import DomainCluster as domclust
from util import getAsnAndOrganisation, SetGrab
import config
#import config_brian as config

class CanNotMergeException(Exception):
    pass
class CanNotSplitException(Exception):
    pass

class IPBlock():
    """
    This class stores blocks of IP addresses, specified by a start and an end
    IP address. Each block contains a list of domain names that are hosted on
    the block's IP addresses.
    """

    #__slots__=['iprange', 'clusters', 'AS', 'dirtyClusters', 'hasReachedClusterCapacity']
    __slots__=['iprange', 'clusters', 'AS', 'dirtyClusters']

    def __init__(self, first, last=None):
        """
        first: the start IP of the block
        dnames: the hosted domain names
        last: the end address of the block. this can be None, then last=first,
        and the block contains only a single IP
        """
        if not last: last = first
        self.iprange=IPRange(first, last)
        self.clusters=dict()
        self.AS = getAsnAndOrganisation(first)[1]
        self.dirtyClusters=False
        #self.hasReachedClusterCapacity=False

    def __contains__(self, ip):
        """
        returns True only if <ip> is contained in this block's IP addresses
        """
        if IPAddress(ip) in self.iprange:
            return True
        else:
            return False

    def __lt__(self, ipb):
        """
        returns true if the last IP of this block is smaller than the first
        one of the other (<ipb>)
        """
        return (self.last() < ipb.first())

    #def __eq__(self, ipb):
    #    return (self.first() == ipb.first) and (self.last() == ipb.last())

    #def __hash__(self):
    #    return hash(self.iprange)

    def __gt__(self, ipb):
        """
        returns true if the first IP of this block is larger than the last
        one of the other (<ipb>)
        """
        return (self.first() > ipb.last())

    def __repr__(self):
        """
        returns a string in the format [cluster1, cluster2 ,..., <-> start IP, end IP
        """
        return (unicode([ck for ck in self.clusters.keys()]) + u' <-> ' +
                unicode(self.iprange))

    def __len__(self):
        """
        returns the number of IP addresses contained in this block
        """
        return len(self.iprange)

    def first(self):
        """
        returns the first IP address of this block
        """
        return self.iprange.first

    def last(self):
        """
        returns the last IP address of this block
        """
        return self.iprange.last

    def updateRange(self, first, last):
        """
        sets a new IP range for this block. this overwrites the old range.

        !!!
        NOTE: this does *not* update the activeIPs field in this IPBlock's
        clusters!
        !!!

        """
        self.iprange = IPRange(first, last)

    def getDomains(self):
        """
        Returns the DomainStr object contained in this IPBlock as a set. This
        runs over all clusters of this block and collects the domains from
        there.
        """
        domains=set()
        for cluster in self.clusters.itervalues():
            domains=domains.union(cluster.domains)
        return domains

    def getNumDomains(self):
        """
        Returns the number of domains stored in this block.

        NOTE: this should be used only at the end of a time bin, as only then
        <self.domains> is properly filled. Remember that we empty
        <self.domains> at every begin of a new time bin!
        """
        domains=self.getDomains()
        return len(domains)

    def hasDomain(self, dname):
        """
        if <dname> matches any stored domain, return True. Else False.
        """
        for cluster in self.clusters.itervalues():
            if dname in cluster:
                return True
        return False

    def _getIPIndex(self, ip):
        ipIndex = int(ip)-self.first()
        try:
            assert 0<=ipIndex<=(self.last()-self.first())
        except AssertionError:
            logging.error('IP not belonging to this block:',ip, self.iprange, ipIndex)
            raise AssertionError
        return ipIndex

    def hitDomainAndIP(self, dname, ip, createBackRef=True):
        """
        If <dname> is contained in any cluster of this block, of <dname> fits
        to any collapsed cluster of this block, we remember that we saw <dname>
        by adding to this block's <domains> set, and setting the corresponding
        bit/flag in the fitting cluster.

        createBackRef: boolean flag, creates a back references in <dname.ipblocks>
        if set to True

        returns True if a fitting cluster was found, else returns False.
        """

        """
        Find the cluster to which the domain belongs
        """
        cl = self.getClusterForDomain(dname, exactMatchesOnly=False)
        if not cl:
            """
            The domain is not contained in any cluster, and doesn't fit to any
            collapsed one
            """
            return False
        else:
            """
            Found a cluster to which <dname> fits
            """
            clusterKey, cluster = cl
            if cluster.isCollapsed and (not dname in cluster):
                if len(cluster) < config.maxClusterSize:
                    """
                    store the domain in the collapsed cluster, to be able to
                    evaluate later if we should still keep this cluster because
                    it is still being used. More precisely, it must be used
                    often enough that we would always again collapse this
                    cluster, i.e. it must contain more than maxClusterSize
                    domains. We stop adding to the cluster as soon as we have
                    more than maxClusterSize domains stored, in order to not
                    waste space.
                    """
                    self.addToCluster(dname, clusterKey)
                    if createBackRef:
                        dname.addIPBlock(self)
                else:
                    """
                    we ignore all domains that fit to a collapsed cluster when
                    this cluster is already full
                    """
                    pass
            else:
                """
                <dname> is already contained in <cluster>. Add <dname> to
                the IPBlock's domain set to remember that we saw this domain in
                the current time bin already.
                """
                if createBackRef:
                    dname.addIPBlock(self)

            if ip:
                """
                Remember that <ip> was actually being used for <cluster> in
                this time bin. That implies that this cluster is not outdated.
                """
                ipIndex=self._getIPIndex(ip)
                cluster.setIpActive(ipIndex)

            return True

    def addDomain(self, d, ip=None, createBackRef=True):
        """
        add a single new domain to this block; creates a back-reference in
        <d.ipblocks> to this block

        d: a DomainStr object
        ip: a netaddr.IPAddress object
        createBackRef: boolean flag, creates a back references in <d.ipblocks>
        if set to True

        returns:
        0: if <d> is already contained in this IPBlock or <d> is close to an
        existing collapsed cluster
        1: if <d> could be added to an existing, not collapsed cluster
        2: if we had to create a new cluster for <d>, or we had to recluster
        everything again
        3: if we would have wanted to create a new cluster, but couldn't
        because the IPBlock reached maxNumClusters*len(IPBlock)
        """

        """
        First we check if we already saw this mapping before. In this case we
        simply remember that we now saw it again, and return.
        """
        if self.hitDomainAndIP(d, ip):
            return (0, 0.0)

        """
        in the following we assume that the domain is not already stored in
        this IPBlock. this should be the case if hitDomainAndIP works
        correctly, but you never know. checking that here consumes time though.
        """
        #assert (not d in self.getDomains())

        """
        This is a new mapping, let's find a cluster for it
        """
        if not self.clusters:
            """
            not a single cluster yet: create one for this <dname>
            """
            newClusterCenter=self.addCluster(d)
            if ip:
                ipIndex=self._getIPIndex(ip)
                self.clusters[newClusterCenter].setIpActive(ipIndex)
            if createBackRef:
                d.addIPBlock(self)
            return (2, 0.0)
        else:
            """
            we already have clusters in this IPBlock; let's see if we can
            find one where <dname> fits in, i.e. one with a distance to
            <dname> not larger than clusteringThreshold
            """
            dists = []
            for ck, cluster in self.clusters.iteritems():
                """
                It doesn't make sense to even consider collapsed clusters here
                again. If <d> is close enough to such a collapsed cluster, this
                was found already above in hitDomainAndIP, so we don't need to
                do that again.
                """
                if not cluster.isCollapsed:
                    dist = domclust.domainDist(ck, d)
                    dists.append((dist, ck))

                    # FIXME, testing only (Mirko's idea)
                    #if dist<=config.clusteringThreshold:
#                        """
#                        we just need to find a cluster that is a good enough
#                        representative, not necessarily the *best* cluster
#                        """
#                        break

            """
            the best cluster is the one to which <d> has the minimum distance
            """
            if dists:
                minDist, clusterKey = min(dists)
            else:
                minDist=1.0

            if minDist<=config.clusteringThreshold:
                """
                we found a matching cluster, which MUST be a not collapsed one
                (see above)
                """
                self.addToCluster(d, clusterKey)

                if createBackRef:
                    d.addIPBlock(self)
                return (1,minDist)
            else:
                """
                we found NO matching cluster
                """
                if self.hasReachedClusterCapacity():
                    """
                    we cannot create another cluster as we already reached the
                    configured maximum. maybe reclustering would help, but this
                    would also remove all empty clusters. this we want to do
                    only at the end of a time bin, therefore we simply ignore
                    this domain for now, hoping that after reclustering later
                    and seeing it again, we can deal with it.
                    """
                    #return (2,minDist)
                    return (3, minDist)
                else:
                    """
                    let's create a new cluster for this domain
                    """
                    newClusterCenter=self.addCluster(d)
                    if ip:
                        ipIndex=self._getIPIndex(ip)
                        self.clusters[newClusterCenter].setIpActive(ipIndex)
                    if createBackRef:
                        d.addIPBlock(self)
                    self.dirtyClusters=True
                    return (2,minDist)

    def addDomains(self, dnames):
        """
        add multiple new domains to this block. dnames is a list of DomainStr
        objects.
        """
        for dname in dnames:
            self.addDomain(dname)

    def addCluster(self, domain, collapsed=False):
        """
        Adds a new cluster containing only <domain>. The key identifying the
        cluster is identical to <domain> but is a new DomainStr object that is
        not being saved in self.domains or any lookup indexes.

        <domain> is a DomainStr object
        """
        if not isinstance(domain, domclust.DomainStr):
            raise TypeError('cannot add cluster for'+unicode(domain))
        else:
            clusterCenter = domclust.DomainStr(domain)
            cluster=domclust.DomainCluster(domain, isCollapsed=collapsed)
            cluster.initActiveIPs(len(self))
            self.clusters[clusterCenter]=cluster

            #if len(self.clusters)>(config.maxNumClusters*len(self)):
#            if len(self.clusters)>(config.maxNumClusters * (1 +
#                np.log(len(self)))):
#                self.hasReachedClusterCapacity=True

            return clusterCenter

    def addToCluster(self, domain, clusterKey):
        """
        Add <domain> to the cluster identified by <clusterKey>. If this causes
        the cluster size to exceed <config.maxClusterSize>, the cluster gets
        collapsed.
        """
# FIXME, debugging
        #msg='clusterKey: '+unicode(clusterKey)
        #msg=msg.encode('utf-8')
        #logging.info(msg)

        try:
            cluster = self.clusters[clusterKey]
        except KeyError:
            logging.error('cluster',clusterKey,'not found in',str(self))
        else:
            cluster.add(domain)
            if len(cluster)>config.maxClusterSize:
                """
                FIXME: should we also make this depended on this check?
                domclust.clusterDispersion(cluster.domains)<=config.clusteringThreshold
                """
                cluster.isCollapsed=True

    def setIPsInactive(self):
        """
        Sets all IPs to 'inactive' in all clusters of this IPBlock
        """
        for cl in self.clusters.itervalues():
            cl.setAllIPsInactive()

    def flushDomains(self):
        """
        Remove all DomainStr objects from this IPBlock, i.e. from all
        clusters in self.clusters.
        """
        for cluster in self.clusters.itervalues():
            """
            remove all back references to this IPBlock
            """
            for dnameObj in cluster.domains:
                dnameObj.removeIPBlock(self, warn=True)
            cluster.flushDomains()

        assert (not len(self.getDomains()))

    def uncollapseClusters(self):
        """
        Converts collapsed clusters to normal clusters if the collapsed cluster
        contains less then config.maxClusterSize domains.
        """
        collapsedClusters = self.getCollapsedClusters()
        uncollapsedClusterKeys=[]
        for ck,cluster in collapsedClusters:
            if len(cluster)<config.maxClusterSize:
                cluster.isCollapsed=False
                uncollapsedClusterKeys.append(ck)
        return uncollapsedClusterKeys

    def hasReachedClusterCapacity(self):
        return len(self.clusters)>=(config.maxNumClusters * (1 + np.log(len(self))))

    def removeEmptyClusters(self):
        """
        Removes all clusters from this IPBlock that do not contain at least a
        single domain.
        """
        emptyClusterKeys=[ck for ck,cv in self.clusters.iteritems() if
                len(cv)==0]
        for ck in emptyClusterKeys:
            self.clusters.pop(ck)

        """
        Let's check if we can accept new clusters again
        """
        #if len(self.clusters)<=(config.maxNumClusters*len(self)):
#        if len(self.clusters)<(config.maxNumClusters * (1 +
#            np.log(len(self)))):
#            self.hasReachedClusterCapacity=False

    def getDomainStr(self, dname):
        """
        Return the DomainStr object from self.domains that corresponds to
        <dname>. Return None if not matching object is found.
        """
        g=SetGrab(dname)
        if g in self.getDomains():
            return g.actual_value
        else:
            return None

#    def removeDomain(self, dnameObj, warn=True):
#        """
#        Removes <dnameObj> from self.domains, and removes <self> from
#        dnameObj.ipblocks
#        """
#        try:
#            dnameObj.removeIPBlock(self, warn=False)
#        except KeyError:
#            """
#            this IPBlock is not referred to in the DomainStr object.
#            This happens when the DomainStr object is the median of a
#            collapsed cluster, and is therefore not known to the
#            elements in the domain factory
#            """
#            msg=('could not remove '+unicode(dnameObj)+' from IPBlock'
#                +str(self))
#            msg=msg.encode('utf-8')
#            logging.warn(msg)

    def isRightNeighbor(self, ipb):
        """
        returns True when the IP address following the last one of this block
        is equal to the first IP address of the other block (<ipb>)
        """
        return ((self.last()+1) == ipb.first())

    def mergeWithRightNeighbor(self, ipb):
        """
        merges the content of this block with <ipb>. This requires that <ipb>
        is a right neighbor of this IPBlock, and that for each domain in each
        block there is a match in the other one. The new IPBlock will then
        contain the domain names of this IPBlock.

        returns the merged block, or throws a CanNotMergeException
        """
        if self.isRightNeighbor(ipb):
            ipbDomains=ipb.getDomains()

            for d in ipbDomains:
                """
                remove all back references to <ipb>, as it is going to be
                merged to <self>
                """
                d.removeIPBlock(ipb, warn=True)

            """
            Find out which IPs in the new block were set to 'active' in any of
            the clusters of the two old blocks. Then update the IP range of
            <self> to contain also the IPs of <ipb>.
            """
            selfActiveIPs = self.getActiveIPs()
            ipbActiveIPs = ipb.getActiveIPs()

            """
            this handles the special case when we are merging IPBlocks with
            missing IPs between them; this can only happen when we omit the
            corresponding check in mergeConditionMet
            """
            missingActiveIPs = np.zeros((ipb.last()-self.first()+1) -
                    (len(selfActiveIPs)+len(ipbActiveIPs)))
            """
            this is currently disabled, remove this assertion if needed
            """
            assert not len(missingActiveIPs)

            """
            the old (left) IPBlock now extends until the end IP of the other
            old (right) IPBlock
            """
            oldIPAddrCnt=len(self)
            oldEndOfBlockAddr=int(self.last())
            self.updateRange(self.first(), ipb.last())

            """
            set the active IPs for each cluster of the updated IPBlock
            """
            for cv in self.clusters.itervalues():
                activeIPs=np.append(cv.activeIPs, missingActiveIPs)
                #cv.activeIPs=np.append(activeIPs, ipbActiveIPs)
                cv.activeIPs=np.append(activeIPs, np.zeros(len(ipbActiveIPs)))

            """
            we increased the IPrange in this block, so we can now store more
            clusters than before; therefore there's no need to make this
            new IPBlock accept no more clusters
            """
            #self.hasReachedClusterCapacity=False

            """
            TESTING
            insert all domains from <ipb> in <self>
            """
            for d in ipbDomains:

                if not d:
                    logging.warn('encountered "None" DomainStr when merging ' +
                            str(self))
                    continue

                clust = ipb.getClusterForDomain(d, exactMatchesOnly=True)

                if not clust:
                    msg='no cluster found for ' + unicode(self) + ' in ' + str(ipb)
                    msg=msg.encode('utf-8')
                    logging.warn(msg)
                    continue

                ck,_=clust
                activeClIPs=ipb.clusters[ck].activeIPs
                newCluster=None

                for oldIPIndex,isSet in enumerate(activeClIPs):
                    if isSet:
                        if newCluster:
                            """
                            we already added this domain to the IPBlock, now
                            let's just update only the IP address usage
                            tracker, this is faster
                            """
                            ipIndex=(oldIPAddrCnt + len(missingActiveIPs) +
                                    oldIPIndex)
                            newCluster.setIpActive(ipIndex)
                        else:
                            ip=IPAddress(oldEndOfBlockAddr + len(missingActiveIPs)
                                    + oldIPIndex + 1)
                            addResult=self.addDomain(d, ip=ip, createBackRef=True)

                            if addResult[0]==3:
                                """
                                we tried to add the domain, and it didn't fit
                                to any existing cluster, but this IPBlock
                                doesn't accept any more new clusters; we
                                therefore continue with the next domain
                                """
                                break
                            else:
                                clust = self.getClusterForDomain(d,
                                        exactMatchesOnly=False)
                                assert len(clust)==2
                                _,newCluster=clust

            """
            we got new domains now, therefore we need to recluster. note that
            by calling _doCluster we force reclustering. We give <activeIPs> to
            the clustering function to let it know which IPs should be set to
            active in any of the new clusters to be created.
            """
            #selfActiveIPs = self.getActiveIPs()
            #self._doCluster(selfActiveIPs)

            """
            add also the collapsed clusters of <ipb>, as they were not copied
            above (they are not in self.domains!). if they are not used
            anymore in the future, they'll be deleted automatically.
            """
            #collapsedClusters = ipb.getCollapsedClusters()
            #for ck,cv in collapsedClusters:
            #    cv.activeIPs=np.copy(activeIPs)
            #    self.clusters[ck]=cv

            return self
        else:
            raise CanNotMergeException()

    def getCollapsedClusters(self):
        """
        Returns a list of tuples (clusterKey, cluster) containing the subset of
        self.clusters that are collapsed.
        """
        collapsedClusters = [(ck,cluster) for ck,cluster in self.clusters.iteritems()
                if cluster.isCollapsed]
        return collapsedClusters

    def getClustersBySize(self):
        """
        Returns the DomainCluster objects in this IPBlock, sorted by size.
        """
        cl = self.clusters.items()
        cl.sort(key=lambda x:len(x[1]))
        return cl

    def getASes(self):
        """
        Returns the set of AS corresponding to the IPs in this IPBlock.
        """
        ASes = set()
        for ip in self.iprange:
            answer = getAsnAndOrganisation(ip)
            if answer:
                ASes.add(answer)
        return ASes

    def getActiveIPs(self):
        """
        The set of active IPs is the logical OR of the sets of IPs active per
        cluster, i.e. an IP is active for this block if it is active in ANY
        cluster.
        """
        activeIPs = np.array(np.zeros(len(self)), dtype=np.bool)
        for cluster in self.clusters.itervalues():
            activeIPs = np.logical_or(activeIPs, cluster.activeIPs)
        return activeIPs

    def _doCluster(self, activeIPs=None):
        """
        Overwrite the old clusters and compute fresh clusters for self.domains
        """

        """
        Remember to which cluster each of the domains belonged so far, in
        order to be able to set the active IPs per new cluster accordingly
        """
        if activeIPs==None:
            domainToCluster=dict()
            for clusterKey, cluster in self.clusters.iteritems():
                for domain in cluster.domains:
                    domainToCluster[domain]=clusterKey

        """
        Compute the new clusters for all domains stored in this IPBlock.
        """
        domains=self.getDomains()
        newClusters = domclust.domainCluster(domains, config.clusteringThreshold)

        """
        TESTING: alternative clustering using DBSCAN
        """
        #if self.clusters:
        #    minPt=min([len(cl) for cl in self.clusters.iteritems()])
        #    newClusters = domclust.domainClusterDBSCAN(domains,
        #            config.clusteringThreshold, minPt)
        #else:
        #    newClusters = domclust.domainClusterDBSCAN(domains,
        #            config.clusteringThreshold)

        """
        Correct the active IPs setting per cluster
        """
        for clusterKey, cluster in newClusters.iteritems():
            if activeIPs==None:
                """
                Find out which IPs are set to active in the old cluster, and set them
                accordingly in the new clusters
                """
                newActiveIPs = np.array(np.zeros(len(self)), dtype=np.bool)

                for domain in cluster.domains:
                    try:
                        ck=domainToCluster[domain]
                    except KeyError:
                        logging.error('BUG: '+domain)
                        logging.error('BUG: '+str(self.getDomains()))
                    else:
                        oldCluster = self.clusters[domainToCluster[domain]]
                        newActiveIPs = np.logical_or(newActiveIPs, oldCluster.activeIPs)
                        if not len(np.nonzero(newActiveIPs)):
                            """
                            all IPs in this cluster seem to be active, we can stop
                            checking the remaining domains
                            """
                            break

                    """
                    newActiveIPs represents now the 'active' status of the
                    entire new cluster, as collected from all the cluster to
                    which the domains belonged previously
                    """
                    cluster.activeIPs = newActiveIPs
            else:
                """
                Force the activeIPs setting to be set according the function's
                parameter
                """
                cluster.activeIPs = np.copy(activeIPs)

        """
        we allow config.maxNumClusters per IP in this IPBlock; if there are
        more, we switch to not accepting any more from now on
        """
        #if len(newClusters)>(config.maxNumClusters*len(self)):
        #if len(self.clusters)>(config.maxNumClusters * (1 +
        #    np.log(len(self)))):
        #    self.hasReachedClusterCapacity=True

        """
        Everything's clustered now, remember that
        """
        self.clusters = newClusters
        self.dirtyClusters = False

        """
        Find out if there are any large clusters that should be collapsed now
        """
        for clusterKey, cluster in self.clusters.iteritems():
            #if (len(cluster)>config.maxClusterSize and
            #    domclust.clusterDispersion(cluster.domains) <=
            #    config.clusteringThreshold):
            if len(cluster)>config.maxClusterSize:
                cluster.isCollapsed=True

    def cluster(self):
        """
        Computes clusters for self.domains, given that this is required because
        something changed.
        """
        if self.dirtyClusters:
            if not self.getDomains():
                """
                There are no more domains in this IPBlock, re-initialize the clusters
                """
                self.clusters.clear()
                self.dirtyClusters=False
            else:
                numClusters=len(self.clusters)

                """
                as there are domains in this IPBlock, there must also be
                clusters that contain them
                """
                assert(numClusters)

                if numClusters==1:
                    """
                    There's only one cluster. All domains in that cluster MUST be
                    well represented by the cluster's center, else they wouldn't be
                    in there. Therefore there's no need to recluster.
                    """
                    self.dirtyClusters=False
                else:
                    """
                    remember the centers of the current empty clusters, they'd
                    get lost during reclustering
                    """
                    emptyClusters=[(ck,cv) for ck,cv in self.clusters.iteritems() if not
                        len(cv)]

                    """
                    We have domains in this IPBlock and have more than one cluster.
                    It could be that we meanwhile flushed inactive domains,
                    therefore reclustering could result in a lower number of
                    clusters.
                    """
                    self._doCluster()

                    """
                    add again the old empty clusters, we keep them until we
                    actively remove them
                    """
                    for ck,cv in emptyClusters:
                        if not ck in self.clusters:
                            """
                            take care to not overwrite a cluster we just
                            created with an old, empty one
                            """
                            self.clusters[ck]=cv

#    def collapseCluster(self, clusterKey):
#        """
#        Removes all domains in the cluster identified by <clusterKey> from
#        self.domains and instead inserts the single element <commonName>, with
#        the weight sum(weight(<domains>)). First, we delete the cluster with
#        key=<clusterKey>, then we remove all <domains>, then we insert
#        <clusterKey> and make it a cluster on it's own.
#
#        <domains> is a list of DomainStr objects.
#        <commonName> is a DomainStr object.
#        """
#        try:
#            cluster = self.clusters[clusterKey]
#        except KeyError:
#            logging.warn(u'cannot collapse cluster '+unicode(clusterKey))
#        else:
#            if not cluster.isCollapsed:
#
#                cluster.isCollapsed=True
#
#                #domains = cluster.domains
#                #self.clusters.pop(clusterKey)
#
#                #for d in domains:
#                #    self.removeDomain(d, warn=True)
#
#                """
#                We are adding domains to clusters to which center they are close.
#                But this doesn't change the cluster center, so for representing all
#                domains as good as possible, we compute now the actual median of
#                all these domains, and use this as the center of the new collapsed
#                cluster.
#                """
#                #newMetaDomain = domclust.domainMedian(domains)
#                #newClusterKey=self.addCluster(newMetaDomain, collapsed=True)
#
#                """
#                Remember which IPs were active
#                """
#                #self.clusters[newClusterKey].activeIPs = np.copy(cluster.activeIPs)
#
#                """
#                return the key identifying the new collapsed cluster; note again
#                that this is not necessarily the same as <clusterKey>
#                """
#                #return newClusterKey

    def _findBestCollapsedCluster(self, dname):
        """
        Find the collapsed cluster with the minimum distance of the cluster center to
        <dname>. Returns a tuple (clusterKey, cluster) if this distance is also
        <= config.clusteringThreshold. Else returns None.
        """
        collapsedClusters = self.getCollapsedClusters()
        if collapsedClusters:
            dists = []
            for ck, cv in collapsedClusters:
                dist=domclust.domainDist(ck, dname)
                if dist<=config.clusteringThreshold:
                    dists.append((dist, ck))

            if dists:
                minDist, bestClusterKey = min(dists)
                return (bestClusterKey, self.clusters[bestClusterKey])
            else:
                return None
        else:
            return None

    def _findCollapsedCluster(self, dname):
        """
        Find a collapsed cluster that has at most a distance of
        config.clusteringThreshold to <dname>. Return None if no such cluster
        can be found.
        """
        collapsedClusters = self.getCollapsedClusters()
        if collapsedClusters:
            for ck, cv in collapsedClusters:
                dist=domclust.domainDist(ck, dname)
                if dist<=config.clusteringThreshold:
                    return (ck, self.clusters[ck])
        return None

    def getClusterForDomain(self, dname, exactMatchesOnly=False):
        """
        Returns a tuple (clusterKey, DomainCluster) describing the cluster to
        which <dname> belongs. Returns None if <dname> is in none of the
        clusters.
        """
        for ck, cv in self.clusters.iteritems():
            if dname in cv:
                return (ck,cv)

        if exactMatchesOnly:
            return None
        else:
            return self._findBestCollapsedCluster(dname)
            #return self._findCollapsedCluster(dname)

    def getEmptyClustersShare(self):
        """
        Returns (number of empty clusters)/(total number of clusters) in this
        IPBlock
        """
        emptyClusters=0
        for c in ipb.clusters.itervalues():
            if not c:
                emptyClusters+=1
        if emptyClusters:
            return emptyClusters/float(len(ipb.clusters))
        else:
            return 0
