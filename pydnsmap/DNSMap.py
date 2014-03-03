import os
from collections import defaultdict
import fnmatch
import time
import logging
import cPickle
import gc
import numpy as np
from netaddr import IPRange
from netaddr.ip import IPAddress, IPNetwork
from RBTree import RBTree
import DomainCluster as domclust
from util import memory_usage
import config
#import config_brian as config
from IPBlock import IPBlock,CanNotMergeException

class timeInterval(object):
    """
    Decorator class that automatically flushes old entries from an DNSMap
    object. Specifically, it deletes DomainStr objects from IPBlock objects
    when the corresponding domain:IP mapping has not been observed in the input
    data for an adjustable time interval (see self.interval). Note that if a
    IPBlock does not contain any more domains after this operation, also the
    IPBlock object is removed from the DNSMap.
    """
    def __init__(self, func):
        self.nextMergeInterval=config.timebinSizeMerge
        self.nextSplitAndCleanupInterval=config.timebinSizeSplitAndCleanup
        self.tNextMerge = None
        self.tNextSplitAndCleanup = None
        self.func = func

    def __call__(self, *args, **kwargs):

        timestamp=args[2]

        if not timestamp:
            """
            sometimes we want to add something to the DNS map without using a
            timestamp; in this case we directly jump to dnsmap.add(..)
            """
            return self.func.__call__(self.obj, *args, **kwargs)

        merged=False
        splitAndCleanedUp=False
        curTime=time.time()
        dnsmap = self.obj
        blocksMerged=set()
        numIPBlocksBeforeMerge=-1

        if not self.tNextMerge:
            self.tNextMerge = timestamp+self.nextMergeInterval
        if not self.tNextSplitAndCleanup:
            self.tNextSplitAndCleanup = timestamp+self.nextSplitAndCleanupInterval

        if timestamp > self.tNextMerge:
            """
            it's time to split and merge blocks
            """
            merged=True

            """
            remember how many IPBlocks we had before merging
            """
            numIPBlocksBeforeMerge=dnsmap.getNumberOfIPBlocks()

# FIXME, remove this: ensure that all IPBlocks are clustered, not just the ones
# that are being merged/split below
            dnsmap.reclusterAll(config.clusteringThreshold, force=False)

            """
            MERGE
            """
            blocksMerged = dnsmap.mergeAllBlocks()
            numBlocksMerged = len(blocksMerged)

            """
            Schedule next merge/split iteration
            """
            self.tNextMerge += self.nextMergeInterval

            """
            output some statistics
            """
            msg=('merged blocks: %u'%(numBlocksMerged))
            logging.info(msg)

        if timestamp > self.tNextSplitAndCleanup:
            """
            we do the cleanup AFTER the split/merge operation, as we need the
            domains set in each of IPBlocks not to be empty in order to cluster
            the domains for splitting/merging. The cleanup procedure *resets*
            the domains field, therefore it has to come after split/merge
            """
            splitAndCleanedUp=True

            """
            SPLIT
            we do this BEFORE calling dnsmap.cleanup(), as this call resets the
            active IP settings, and therefore affects the splitting. We want to
            split blocks only if the corresponding IPs were inactive for an
            entire cleanup time interval.
            NOTE: we do split blocks that were merged in the previous merge
            intervals though!
            """

            numBlocksSplit = dnsmap.splitAllBlocks(blocksMerged)

            """
            remove empty IPBlocks, remove unused domain names, uncollapse
            clusters, and reset all IPBlocks (i.e., reset the set of contained
            domains and set all IPs to not active)
            """
            dnsmap.cleanup()

            """
            After the first cleanup iteration we start to output suspicious
            activity
            """
            dnsmap.doOutputSuspicious=True

            """
            Schedule next cleanup iteration
            """
            self.tNextSplitAndCleanup += self.nextSplitAndCleanupInterval

            """
            output some statistics
            """
            msg=('split blocks: %u'%(numBlocksSplit))
            logging.info(msg)

            """
            dump current dnsmap to disk, omitting the domains
            """
            dnsmap.dumpt(os.path.join(config.workingDir,
                'dnsmap_'+str(timestamp)+'.txt'), withDomains=False)

        if merged or splitAndCleanedUp:
            """
            output some statistics
            """
            msg=('t is now %u; merged: %s; splitAndCleanedUp: %s'%(timestamp,
                merged, splitAndCleanedUp))
            logging.info(msg)
            logging.info('memory usage: '+str(memory_usage()))
            msg=('IPBlocks before merge: %u'%(numIPBlocksBeforeMerge))
            logging.info(msg)
            msg=('IPs/IPBlocks: %u/%u'%(dnsmap.getNumberOfIPs(),
                dnsmap.getNumberOfIPBlocks()))
            logging.info(msg)
            logging.info('domains: '+str(dnsmap.getNumDomains()))
            logging.info('Clusters per IP: '+str(dnsmap.getMeanStdClustersPerIP()))
            logging.info('Clusters per IPBlock: '+str(dnsmap.getMeanStdClustersPerIPBlock()))
            logging.info('Collapsed clusters: '+str(dnsmap.getNumCollapsedClusters()))
            logging.info('Blocks that reached cluster capacity: '+str(len([1 for node in
                dnsmap.traverseTrees() if
                node.value.hasReachedClusterCapacity()])))
            logging.info('this took '+str(time.time()-curTime)+' seconds')

        return self.func.__call__(self.obj, *args, **kwargs)

    def __get__(self, instance, owner):
        self.cls = owner
        self.obj = instance
        return self.__call__

def mergeConditionMet(ipb1, ipb2, domainSimilarityTh, domainCountTh):
    """
    Tests if two IPBlocks <ipb1> and <ipb2> should be merged.
    """

    """
    if the blocks belong to different autonomous systems, we don't merge them
    """
    if not ipb1.AS == ipb2.AS:
        return False

    """
    for evaluating the merging condition, we need an up-to-date cluster
    configuration. maybe we delayed that computation until here, so let's
    check.
    """
    ipb1.cluster()
    ipb2.cluster()

    """
    we cache the distances between the cluster centers here to avoid that we
    have to recompute them again and again
    """
    distances = dict()

    def _match(x,y,numDomains):
        """
        This function checks if x is similar enough to y to be merged. It does
        NOT check if y is similar enough to x!

        x and y are tuples with (clusterKey, set of clustered DomainStr objects)
        """
        numMatchingDomains = 0.0
        domainsLeft = numDomains
        for k1,v1 in x:

            if not len(v1):
                """
                the clusters are sorted according to the number of domains the
                contain, in decreasing order. if <v1> is empty, no other
                cluster will therefore contain anything, therefore we can break
                here
                """
                break

            for k2,v2 in y:
                try:
                    """
                    note the reversed indexes below (k1,k2). this is a trick to
                    let the distances be computed the first time _match() is
                    called, and let them be reused when it is called the second
                    time with reversed parameters.
                    """
                    d = distances[(k2,k1)]
                except KeyError:
                    d = domclust.domainDist(k1,k2)
                    distances[(k1,k2)] = d
                if d <= domainSimilarityTh:
                    """
                    we found the largest cluster in <y> that matches to <k2>.
                    """
                    numMatchingDomains+=len(v1)
                    break

            """
            let's see if we already found enough matches, so that we can exit
            early and save time
            """
            if numMatchingDomains/numDomains >= domainCountTh:
                return True

            """
            does it still make sense to keep searching? we can stop
            when the number of remaining domains is too small to satisfy the
            condition above.
            """
            domainsLeft-=len(v1)
            if (numMatchingDomains+domainsLeft)/numDomains < domainCountTh:
                return False

        """
        not enough matches found
        """
        return False

    """
    sort clusters according to the number of included domains, in
    decreasing order. this should help us to speed up the process to find
    a sufficient number of matching domains.
    """
    ipb1Clusters = sorted(ipb1.clusters.items(), key=lambda x:len(x[1]),
        reverse=True)
    ipb2Clusters = sorted(ipb2.clusters.items(), key=lambda x:len(x[1]),
        reverse=True)

    numDomainsIpb1 = ipb1.getNumDomains()
    numDomainsIpb2 = ipb2.getNumDomains()

    if not numDomainsIpb1 or not numDomainsIpb2:
        return False

    doMerge = _match(ipb1Clusters, ipb2Clusters, numDomainsIpb1)
    if doMerge:
        doMerge = _match(ipb2Clusters, ipb1Clusters, numDomainsIpb2)

    return doMerge

class DNSMap():
    """
    This class stores IPBlock objects in a set of Red-Black-Trees. The idea is to
    split the entire IP address range in a number of ranges depending on the
    netmask of an IP address. this way the depth of the tree can be controlled,
    at the price of spreading the information amongst several tree that don't
    communicate with each other, and which might show some nasty effects at the
    edges of their IP ranges (e.g., when a certain domain maps half to one
    tree, and half to the neighboring one).
    """
    def __init__(self, clusteringThreshold, domainCountThreshold,
            netmask=8):
        """
        startmask defines the number of trees that we are going to use. it
        defaults to 8, which means that for each /8 IP address there is one
        tree (in this case: theoretically 256). Note that the trees are created
        on demand, i.e. when we see the first time an IP address for which not
        yet a tree exists, we create the tree and insert the address there.
        """

        assert 0<=clusteringThreshold<=1
        assert 0<=domainCountThreshold<=1

        self.netmask = '/'+str(netmask)
        self.forest = defaultdict(RBTree)
        self.domainfactory = domclust.DomainStrFactory()
        self.doOutputSuspicious = False

        config.clusteringThreshold = clusteringThreshold
        config.domainCountThreshold = domainCountThreshold

        # FIXME, this should probably be set in config.py
        self.suspiciousFile = open(os.path.join(config.workingDir,
            'suspicious.txt'), 'w')

    def _findTree(self, ip):
        """
        returns the tree containing <ip>
        ip in integer or string format
        """
        ipnw =  IPNetwork(str(IPAddress(ip))+self.netmask).first
        return self.forest[ipnw]

    def _insertIPBlock(self, ipb, iptree=None):
        """
        Insert an IPBlock <ipb> in the tree specified by the first IP address
        of <ipb>, or in <iptree> if not None
        """
        if not ipb: return

        if iptree == None:
            iptree = self._findTree(ipb.first())

        ipbTreeElem = iptree.insertNode(ipb.first(), ipb)
        return ipbTreeElem

    def _removeIPBlock(self, ipb):
        """
        Remove the node that holds <ipb> from the corresponding tree.
        """
        if not ipb: return

        node, iptree = self.getTreeElem(ipb.first())

        if node:
            iptree.deleteNode(node)
        else:
            log.warn('could not remove node for IPBlock',ipb)

    def removeEmptyIPBlocks(self):
        """
        Removes all IPBlocks which have an empty <domains> set, and which do
        not contain collapsed clusters.

        NOTE: this should be used only at the end of a time bin, as only then
        the IPBlocks' <domains> set is properly filled. Remember that we empty
        <domains> at every begin of a new time bin!

        returns the number of deleted IPBlocks
        """
        nodesToDelete = set()
        for node, tree in self.traverseTrees(True):
            ipb = node.value

            if not ipb.getNumDomains():
                """
                this block does not contain any domains and can therefore
                be deleted
                """
                nodesToDelete.add((node.key, tree, ipb))

        """
        we can not delete from the tree while iterating over it, therefore
        we do the deletions here
        """
        for nodeKey, tree, ipb in nodesToDelete:
            node = tree.findNode(nodeKey)
            tree.deleteNode(node)

        """
        we deleted a lot of stuff now, let's invoke the garbage collector
        """
        #gc.collect()

        return (len(nodesToDelete))

    def cleanup(self):
        """
        FIXME: comment me
        """

        """
        First, remove all domains that do not map to any IPBlock anymore from
        the domain factory. this has to be done *before* flushing the domains
        from each individual IPBlock, as flushing from the blocks effectively
        empties the <ipblocks> set of each of the DomainStr object the factory,
        which is exactly the condition we check for when flushing from the
        factory.
        """

        """
        remove IP blocks that do not contain any domains anymore
        """
        numIPBlocksDeleted=self.removeEmptyIPBlocks()
        msg='deleted nodes: %u'%(numIPBlocksDeleted)
        logging.info(msg)

        numDomains=self.getNumDomains()
        self.domainfactory.flushEmptyDomains()
        logging.info('removed '+str(numDomains-self.getNumDomains())+
            ' domains')

        for node, tree in self.traverseTrees(True):
            ipb = node.value

            """
            convert all collapsed clusters that do not contain sufficient
            domains anymore to normal clusters
            """
            ipb.uncollapseClusters()

            """
            remove all clusters that are already empty, even before removing
            the domains from the IP block below
            """
            ipb.removeEmptyClusters()

            """
            flush the set of domains for each IPBlock
            """
            ipb.flushDomains()

            """
            mark all IPs in all clusters in this block as inactive
            """
            ipb.setIPsInactive()

        """
        we deleted a lot of stuff now, let's invoke the garbage collector
        """
        gc.collect()

    def getRightNeighbor(self, ipb, ipbTreeElem, iptree):
        """
        Finds the direct right neighbor of an IPBlock <ipb>. The direct right
        neighbor is the one which satisfies ipb.last+1 == neighbor.first. If
        such a neighbor doesn't exist we return <None>.

        Returns a tuple (rightNeighborBlock, rightNeighborTreeElem)
        """
        rightNeighborTreeElem = iptree.nextNode(ipbTreeElem)
        if rightNeighborTreeElem:
            rightNeighborBlock =  rightNeighborTreeElem.value
            if ipb.isRightNeighbor(rightNeighborBlock):
                return (rightNeighborBlock, rightNeighborTreeElem)
        return None

    def getLeftNeighbor(self, ipb, ipbTreeElem, iptree):
        """
        Finds the direct left neighbor of an IPBlock <ipb>. The direct left
        neighbor is the one which satisfies neighbor.last+1 == ipb.first. If
        such a neighbor doesn't exist we return <None>.

        Returns a tuple (leftNeighborBlock, leftNeighborTreeElem)
        """
        leftNeighborTreeElem = iptree.prevNode(ipbTreeElem)
        if leftNeighborTreeElem:
            leftNeighborBlock =  leftNeighborTreeElem.value
            if leftNeighborBlock.isRightNeighbor(ipb):
                return (leftNeighborBlock, leftNeighborTreeElem)
        return None

    def mergeAllBlocks(self):
        """
        Run over the IPBlocks stored in this DNSMap and try to merge all
        blocks.
        """
        blocksMerged=set()
        for rbtree in self.forest.itervalues():
            node=rbtree.firstNode()
            while True:
                ipb = node.value
                rightNeighborTreeElem = rbtree.nextNode(node)

                if not rightNeighborTreeElem:
                    """
                    Reached the last node in this <rbtree>
                    """
                    break

                rightNeighborBlock = rightNeighborTreeElem.value

                if ipb.isRightNeighbor(rightNeighborBlock):
                    merged = self.mergeIPBlocks(ipb,
                            rightNeighborBlock, rightNeighborTreeElem,
                            rbtree)
                    if merged:
                        blocksMerged.add(str(ipb))
                    else:
                        node=rightNeighborTreeElem
                else:
                    node=rightNeighborTreeElem
        return blocksMerged

    def splitAllBlocks(self, blocksNotToBeSplit=[]):
        """
        Runs over all IPBlocks stored in this DNSMap and tries to split them by
        evaluating the mergeCondition on both halves of each IPBlock.

        blocksNotToBeSplit: a set of IPBlocks that should not be split. The
        blocks are identified by str(block).

        returns the number of blocks that were split
        """
        numBlocksSplit=0

        for rbtree in self.forest.values():
            node = rbtree.firstNode()
            while node:
                ipb = node.value

                if len(ipb)>1 and not str(ipb) in blocksNotToBeSplit:
                    """
                    this block contains more than one IP and was NOT just
                    created by merging, so we can try to split it
                    """
                    ipb1, ipb2 = self.splitIPBlock(ipb)

                    if not mergeConditionMet(ipb1, ipb2,
                            config.clusteringThreshold,
                            config.domainCountThreshold):
                        numBlocksSplit+=1
                        self._removeIPBlock(ipb)
                        node1 = self._insertIPBlock(ipb1, iptree=rbtree)
                        node2 = self._insertIPBlock(ipb2, iptree=rbtree)

                        """
                        update the back-references in the DomainStr
                        objects: remove references to the deleted block,
                        and create reference to the new blocks
                        """
                        for d in ipb.getDomains():

                            """
                            FIXME
                            sometimes it happens that <d> does not contain a back-reference to
                            <ipb> anymore. in fact, in this case <d> does not contain any
                            back-references to IPBlocks. it's unclear why this is happening,
                            for now we ignore this warning.
                            """
                            d.removeIPBlock(ipb, warn=True)
                        for d in ipb1.getDomains():
                            d.addIPBlock(ipb1)
                        for d in ipb2.getDomains():
                            d.addIPBlock(ipb2)

                        """
                        We continue with the block following the ones we
                        just created by splitting <ipb>. That means that
                        these new blocks will at earliest be further split
                        in the next iteration.
                        """
                        node = node2
                node = rbtree.nextNode(node)
        return numBlocksSplit

    def mergeIPBlocks(self, masterIpb, slaveIpb, slaveTreeElem, rbtree):
        """
        Merges two IPBlocks if they are similar enough (see
        _mergeConditionMet()). As a result of this operation, the contents
        of <slaveIpb> will be written to <masterIpb>, and <slaveIpb> will be
        deleted. Note that <slaveIpb> must be the direct right neighbor of
        <masterIpb>, else merging will fail in any case.

        Returns True if merging was successful, else False.
        """
        if mergeConditionMet(masterIpb, slaveIpb,
                config.clusteringThreshold, config.domainCountThreshold):
            try:
                masterIpb.mergeWithRightNeighbor(slaveIpb)
            except CanNotMergeException:
                logging.warn('cannot merge', masterIpb, slaveIpb)
                return False
            else:
                rbtree.deleteNode(slaveTreeElem)
                del slaveIpb
                return True
        else:
            return False

    def splitIPBlock(self, ipb):
        """
        Split <ipb> in two halves.

        Note: this does neither delete <ipb> from the DNSMap nor insert the new
        blocks in it. Also, it doesn't create back-references to the new blocks
        in the containing domains <ipblocks> field. All of this has to be done
        outside of this function in case it is decided that the new blocks
        should be kept.

        returns the two new IPBlocks.
        """

        if len(ipb) == 1:
            return None

        """
        ensure that the IPBlock is properly clustered
        """
        ipb.cluster()

        """
        split <ipb> in two halves, and extract from each halve the domains that
        have been used in this IP range
        """
        splitIndex = int(len(ipb.iprange)/2.0)
        domainsIpb1 = []
        domainsIpb2 = []
        for clusterKey, cluster in ipb.clusters.iteritems():
            activeIPsForIpb1=np.copy(cluster.activeIPs[:splitIndex])
            activeIPsForIpb2=np.copy(cluster.activeIPs[splitIndex:])
            if True in activeIPsForIpb1:
                domainsIpb1+=[(cluster.domains, activeIPsForIpb1)]
            if True in activeIPsForIpb2:
                domainsIpb2+=[(cluster.domains, activeIPsForIpb2)]

        def _createNewIPBlock(firstIP, lastIP, domainsAndActiveIPs,
                ipIndexOffset=0):
            """
            creates a new IPBlock from a set of domains and IPs. Note that we
            do not create back references for these domains.
            """
            newIpb = IPBlock(firstIP, last=lastIP)
            for domains, activeIPs in domainsAndActiveIPs:
                for d in domains:
                    for ipIndex, ipIsActive in enumerate(activeIPs):
                        if ipIsActive:
                            """
                            we DON'T want to create back-references, as we do
                            not know yet if we're going to keep newIpb
                            """
                            ip=ipb.iprange[ipIndex+ipIndexOffset]
                            newIpb.addDomain(d, ip, createBackRef=False)
            newIpb.cluster()
            return newIpb

        """
        create two blocks using the domains that were active in each halve
        """
        ipb1=_createNewIPBlock(ipb.iprange[0], ipb.iprange[splitIndex-1],
                domainsIpb1)
        ipb2=_createNewIPBlock(ipb.iprange[splitIndex], ipb.iprange[-1],
                domainsIpb2, ipIndexOffset=splitIndex)

        return (ipb1,ipb2)

    def getTreeElem(self, ip):
        """
        Returns a tuple with the node that contains <ip> and the containing
        RBTree that contains this node. Return (None, RBTree) if no such node
        exists.

        Note that node.value is an IPBlock object.
        """
        iptree = self._findTree(ip)

        """
        find the IPBlock in the tree that starts at an IP address that is
        closest to <ip>, and SMALLER than <ip>
        """
        treeElem = iptree.findClosestNode(int(IPAddress(ip)))

        if not treeElem:
            return None, iptree

        """
        let's see if this is the 'right' closest block, i.e. the one where
        <ip> is >= the start IP of the block. if this is not the case, we
        pick the block's left neighbor.
        """
        if not ip in treeElem.value:
            treeElem = iptree.prevNode(treeElem)
            if not treeElem or not ip in treeElem.value:
                return None, iptree
            return treeElem, iptree
        else:
            return treeElem, iptree

    def getIPBlock(self, ip):
        """
        Return the IPBlock that contains <ip>. Returns None if no such IPBlock
        is found.
        """
        node,_ = self.getTreeElem(ip)
        if node:
            return node.value
        else:
            return None

    def reclusterAll(self, clusteringThreshold, force=False):
        """
        Set the clustering threshold for all contained IPBlocks to
        <clusteringThreshold>, and force immediate reclustering of all
        IPBlocks.
        """
        config.clusteringThreshold=clusteringThreshold

        for node in self.traverseTrees():
            ipb=node.value

            if force:
                ipb._doCluster()
            else:
                ipb.cluster()

    def _writeSuspicious(self, timestamp, dname, ip, clientID, minDist,
            numDomainsInBlock):
        """
        FIXME: comment me
        """
        d = self.domainfactory.getDomainStr(dname)
        if d:
            numBlocks = len(d.ipblocks)
        else:
            numBlocks = 0
        # NOTE: <dname> may contain non-ascii symbols, that's why we use
        # unicode
        s = ' '.join([str(timestamp), unicode(dname), str(ip), str(clientID),
            str(minDist), str(numBlocks), str(numDomainsInBlock)])
        s=s.encode('utf-8')
        self.suspiciousFile.write(s+'\n')

    @timeInterval
    def add(self, ip, dname, timestamp, clientID=None):
        """
        Add a new IP address/domain name mapping to the tree. Four things can
        happen:

        1) If there is a block that already contains the mapping, nothing is
        done.
        2) If the IP is contained in the block, but not the dname, the block is
        split to create a new block that contains all previous domain names
        plus dname, and only one IP (namely <ip>)
        3) If there is no matching block yet, a new one is created.
        4) If the closest block is a right neighbor of the new block to be
        created, the closest block is extended to contain also the new IP
        address.

        Returns True if a new IPBlock was added, else returns False
        """

        if not ip or not dname:
            msg = unicode('cannot add empty record: %s %s %s'%(ip, dname,
                timestamp))
            logging.info(msg)
            return False

        dname=dname.lower()

        """
        Get the DomainStr object corresponding to <dname> from the factory.
        This ensures that there's always exactly one object for a domain name,
        no matter in how many IPBlocks this object appears
        """
        dnameObj = self.domainfactory.makeDomainStr(dname)

        """
        We need to add this mapping to the IP block that contains <ip>, let's
        find it.
        """
        containingTreeElem, iptree = self.getTreeElem(ip)

        if not containingTreeElem:

            """
            couldn't find a block that contains <ip>, let's create a new one and
            insert it into the tree
            """
            ipb = IPBlock(ip)
            ipb.addDomain(dnameObj, ip)
            ipbTreeElem = self._insertIPBlock(ipb, iptree)

            """
            can we merge this block now with the right/left neighbor?
            """
            #merged = self.mergeWithNeighbors(ipb, ipbTreeElem, iptree)

            if self.doOutputSuspicious:
            #if not merged and self.doOutputSuspicious:
            #    """
            #    This is a new mapping that involves an IP that we didn't see
            #    before. Typically, such IPs are in access provider networks,
            #    and could therefore indicate malicious activity.
            #    """
                self._writeSuspicious(timestamp, dname, ip, clientID, -1
                        ,ipb.getNumDomains())

            return True
        else:
            """
            found an existing IPBlock for this IP
            """
            ipb = containingTreeElem.value

            """
            let's try to add this mapping to the <ipb>
            """
            addResultCode, minDist = ipb.addDomain(dnameObj, ip)
            """
            addResult==0 and addResult==1 mean that we were able to integrate
            the mapping in the block without changing the clusters
            """

            if addResultCode==2:
                """
                adding this mapping changed the cluster configuration, which
                means that we found no good fit to this IPBlock. This seems
                suspicious.
                """
                if self.doOutputSuspicious and minDist>0.0:
                    self._writeSuspicious(timestamp, dname, ip, clientID,
                            minDist, ipb.getNumDomains())

                return True
            elif addResultCode==3:
                """
                the domain does not fit, but we cannot create a new cluster;
                therefore we ignore this domain for now, hoping that we may be
                able to consider it in the future after reclustering and
                merging
                """
                #msg=('Could not create cluster: %s %s'
                #        ' %s'%(unicode(dnameObj),
                #        str(ip), str(timestamp)))
                #msg=msg.encode('utf-8')
                #logging.info(msg)
                return False
            else:
                return False

    def traverseTrees(self, returnContainingTree=False, sortedByIP=False):
        """
        Generator that returns at each iteration an IPBlock from this DNSMap
        object.
        """

        if sortedByIP:
            forest=self.forest.items()
            forest.sort(key=lambda x:x[0])
            _,trees=zip(*forest)
        else:
            trees=self.forest.itervalues()

        for tree in trees:
            for node in tree.traversalGenerator():
                if node:
                    if returnContainingTree:
                        yield (node, tree)
                    else:
                        yield node

    def findIPBlocksForDname(self, dname):
        """
        Returns all IPBlocks that contain domains matching <dname>. Note that
        you can use wildcard in <dname>, check out the documentation of the
        fnmatch module.

        NOTE: this does not find those IPBlocks where <dname> is contained in a
        collapsed cluster.
        """
        if '*' in dname:
            results = []
            for node in self.traverseTrees():
                ipb=node.value
                if fnmatch.filter(ipb.getDomains(), dname):
                    results.append(ipb)
        else:
            d = self.domainfactory.getDomainStr(dname)
            if d:
                results = list(d.ipblocks)
            else:
                results = None
        return results

    def getNumberOfIPBlocks(self):
        """
        """
        cnt=0
        for node in self.traverseTrees():
            cnt+=1
        return cnt

    def getMeanStdClustersPerIP(self):
        """
        Return the mean, standard deviation, and standard error for the number
        of clusters per IP address in this DNSMap
        """
        numClusters=[]
        for node in self.traverseTrees():
            ipb=node.value
            numClustersInIPBlock=len(ipb.clusters)
            if numClustersInIPBlock:
                numClusters.append(numClustersInIPBlock/float(len(ipb)))
        m=np.mean(numClusters)
        std=np.std(numClusters)
        #stderr=std/np.sqrt(len(numClusters))
        #return (m, std, stderr)

        return (m,std,np.percentile(numClusters, list(np.arange(5,105,5))))

    def getMeanStdClustersPerIPBlock(self):
        """
        Return the mean, standard deviation, and standard error for the number
        of clusters per IPBlock in this DNSMap
        """
        numClusters=[]
        for node in self.traverseTrees():
            ipb=node.value
            numClusters.append(len(ipb.clusters))
        m=np.mean(numClusters)
        std=np.std(numClusters)
        #stderr=std/np.sqrt(len(numClusters))
        #return (m, std, stderr)

        return (m,std,np.percentile(numClusters, list(np.arange(5,105,5))))

    def getNumCollapsedClusters(self):
        """
        Returns the total number of collapsed clusters for all IPBlocks in
        this DNSMap
        """
        numCollapsed=0
        for node in self.traverseTrees():
            ipb=node.value
            numCollapsed+=len(ipb.getCollapsedClusters())
        return numCollapsed

    def getNumberOfIPs(self):
        """
        Returns the number of IPs that are contained by this DNSMap object,
        i.e. all IPs in the IPranges in all of the contained RBTrees.
        """
        cnt=0
        for node in self.traverseTrees():
            ipb=node.value
            cnt+=len(ipb)
        return cnt

    def getNumDomains(self):
        """
        Returns the number of domain names stored in this DNSMap object,
        i.e. all domain names in self.domainfactory. Note that this does not
        necessarily include the all domains that are contained exclusively in
        collapsed clusters, as not all of them are stored in the domainfactory
        """
        return len(self.domainfactory.domains)

    def getDnamesCount(self):
        """
        Returns a dict with <domain name>:<cnt>, where <cnt> represents the
        number of IPBlocks in which this domain name was found.
        """
        dnames = dict()
        for dname in self.domainfactory.domains:
            dnames[dname]=len(dname.ipblocks)
        return dnames

    def getIPBlocksForDnames(self, searchedDname=None):
        """
        Returns a dict with <domain name>:<IPBlocks>, i.e. all IP blocks where
        a domain name maps to. The optional argument <searchedDname> restricts
        the output to domains that match the given pattern which can also
        include (fnmatch) wildcards.
        """
        dnamesBlocks = defaultdict(list)
        for node in self.traverseTrees():
            ipb=node.value
            for dname in ipb.getDomains():
                if searchedDname:
                    if fnmatch.fnmatch(dname, searchedDname):
                        dnamesBlocks[dname].append(ipb)
                else:
                    dnamesBlocks[dname].append(ipb)
        return dnamesBlocks

#    @staticmethod
#    def load(filename):
#        """
#        Loads an IPBlocks object from a pickled file.
#        """
#        iptree=None
#        with open(filename, 'rb') as f:
#            iptree = cPickle.load(f)
#        return iptree
#
#    def dump(self, filename):
#        """
#        Pickles this object to file <filename>
#        """
#        with open(filename, 'wb') as f:
#            cPickle.dump(self, f, cPickle.HIGHEST_PROTOCOL)

    def dumpt(self, filename, withDomains=False):
        """
        Dumps the content of this DNSMap to a text file. Each line represent
        one IPBlock, the format is:
        FIRST_IP LAST_IP clusterKey1;clusterKey2;[..];\n

        if <withDomains>==True, the output is:
        FIRST_IP LAST_IP
        clusterKey1:domain1,domain2,[..];clusterKey2:domain3,domain4,[..];[..];\n
        """
        with open(filename, 'w') as f:
            for node in self.traverseTrees():
                ipb=node.value
                ipb.cluster()
                if ipb.clusters:
                    if ipb.hasReachedClusterCapacity():
                        f.write('*')
                    f.write(str(ipb.first())+' ')
                    f.write(str(ipb.last())+' ')
                    if withDomains:
                        for ck,cv in ipb.clusters.iteritems():

                            """
                            Add '*' prefix to collapsed clusters
                            """
                            if cv.isCollapsed:
                                ck='*'+ck

                            f.write(ck.encode('utf-8')+':')
                            s=','.join([d.encode('utf-8') for d in cv.domains])
                            f.write(s)
                            f.write(';')
                    else:
                        for ck,cv in ipb.clusters.iteritems():
                            """
                            Add '*' prefix to collapsed clusters
                            """
                            if cv.isCollapsed:
                                ck='*'+ck
                            f.write(ck.encode('utf-8')+';')
                    f.write('\n')

    @staticmethod
    def loadt(filename, clusteringThreshold, domainCountThreshold,
            withDomains=True):
        """
        Loads the text format written by dumpt() and returns a DNSMap object
        that represents the data in <filename>.
        """
        dnsmap=DNSMap(clusteringThreshold, domainCountThreshold)
        with open(filename, 'r') as f:
            logging.warn('loading DNSMap from '+str(filename))
            for line in f:
                if not line:
                    continue

                line=line.rstrip('\n')
                line=line.rstrip(' ')
                splitLine=line.split()

                try:
                    if splitLine[0].startswith('*'):
                        #hasReachedClusterCapacity=True
                        firstIP=IPAddress(splitLine[0][1:])
                    else:
                        #hasReachedClusterCapacity=False
                        firstIP=IPAddress(splitLine[0])

                    lastIP=IPAddress(splitLine[1])
                    ipb=IPBlock(firstIP, last=lastIP)
                    #ipb.hasReachedClusterCapacity=hasReachedClusterCapacity

                    clusters=(splitLine[2]).split(';')
                    for cluster in clusters:
                        if not cluster:continue

                        isCollapsed=False

                        """
                        remove '*' prefix for collapsed clusters
                        """
                        if cluster.startswith('*'):
                            isCollapsed=True
                            cluster=cluster.lstrip('*')

                        try:
                            try:
                                index=cluster.index(':')
                            except ValueError:
                                ckDname=domclust.DomainStr(cluster)

                                # create an empty cluster in this IPBlock
                                cluster=domclust.DomainCluster([],
                                        isCollapsed=isCollapsed)
                                cluster.initActiveIPs(len(ipb))
                                ipb.clusters[ckDname]=cluster

                            else:
                                """
                                seems we also exported domain names
                                """
                                ck=cluster[:index]
                                clusteredDomains=cluster[index+1:].split(',')
                                ckDname=domclust.DomainStr(ck)

                                # create an empty cluster in this IPBlock
                                cluster=domclust.DomainCluster([],
                                        isCollapsed=isCollapsed)
                                cluster.initActiveIPs(len(ipb))
                                ipb.clusters[ckDname]=cluster

                                if withDomains:
                                    for d in clusteredDomains:
                                        dname=dnsmap.domainfactory.makeDomainStr(d)
                                        dname.addIPBlock(ipb)
                                        ipb.addToCluster(dname, ckDname)
                        except UnicodeDecodeError:
                            continue
                except IndexError:
                    continue
                else:
                    dnsmap._insertIPBlock(ipb)

        return dnsmap
