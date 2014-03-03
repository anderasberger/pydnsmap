"""
This code is based on a PqQt4 demo by Eli Bendersky (eliben@gmail.com)
"""
import sys, os, random
import re
from collections import defaultdict
import operator
import time
import gc
import math
from PyQt4.QtCore import *
from PyQt4.QtGui import *

import matplotlib
matplotlib.use('Qt4Agg', warn=True)
from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt4agg import NavigationToolbar2QTAgg as NavigationToolbar
#from matplotlib.figure import Figure
from matplotlib.pyplot import figure
import networkx as nx
import numpy as np
import netaddr

import util
import analysis

MAX_NODES_FOR_PLOTTING_GRAPH_=1000

class MyTableModel(QAbstractTableModel):
    def __init__(self, datain, headerdata, parent=None, *args):
        QAbstractTableModel.__init__(self, parent, *args)
        self.arraydata = datain
        self.headerdata = headerdata

    def rowCount(self, parent=None):
        if self.arraydata:
            return len(self.arraydata)
        else:
            return 0

    def columnCount(self, parent=None):
        if self.arraydata:
            return len(self.arraydata[0])
        else:
            return 0

    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return QVariant(self.headerdata[col])
        return QVariant()

    def sort(self, Ncol, order):
        """Sort table by given column number.
        """
        newdata = sorted(self.arraydata, key=operator.itemgetter(Ncol))
        if order == Qt.DescendingOrder:
            newdata.reverse()
        self.updateTableData(newdata)

    def updateTableData(self, newdata):
        self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self.arraydata = newdata
        self.emit(SIGNAL("layoutChanged()"))

class DomainsTableModel(MyTableModel):
    def __init__(self, datain, headerdata, parent=None, *args):
        MyTableModel.__init__(self, datain, headerdata, parent, *args)

    def data(self, index, role):
        if not index.isValid():
            return QVariant()
        else:
            if role == Qt.CheckStateRole and index.column() == self.columnCount() - 1:
                if self.arraydata[index.row()][index.column()]:
                    return Qt.Checked
                else:
                    return Qt.Unchecked
            elif role == Qt.DisplayRole:
                return QVariant(self.arraydata[index.row()][index.column()])
            return QVariant()

class ComponentsTableModel(MyTableModel):
    def __init__(self, datain, headerdata, parent=None, *args):
        MyTableModel.__init__(self, datain, headerdata, parent, *args)

    def data(self, index, role):
        if not index.isValid():
            return QVariant()
        else:
            if role == Qt.CheckStateRole and index.column() == self.columnCount() - 1:
                if self.arraydata[index.row()][index.column()]:
                    return Qt.Checked
                else:
                    return Qt.Unchecked
            elif role == Qt.DisplayRole:
                return QVariant(self.arraydata[index.row()][index.column()])
            return QVariant()

    def setComponentMalicious(self, componentKey, isMalicious):
        tabledata=[]
        for d in self.arraydata:
            if d[0]==componentKey:
                tabledata.append((d[0], d[1], d[2], d[3], isMalicious))
            else:
                tabledata.append(d)
        self.updateTableData(tabledata)

def loadWhitelistFromFile(filename):
    whitelistPatterns=[]
    try:
        with open(filename) as f:
            for line in f:
                line=line.rstrip('\n')
                try:
                    whitelistPatterns.append(re.compile(line))
                except:
                    print 'could not compile whitelist pattern', line
    except IOError:
        # no whitelist file found
        pass
    return whitelistPatterns

def getDomainsInGraph(graph):
    domainsInGraph=set([d[0] for d in graph.nodes_iter(data=True) if
        d[1]['color']==util.DOMAIN_COLOR])
    return domainsInGraph

def getIPsInGraph(graph):
    ipsInGraph=set([d[0] for d in graph.nodes_iter(data=True) if
        d[1]['color']==util.IP_COLOR])
    return ipsInGraph

def getGraphCommunities(graph):
    from pygraphanalysis import communitydetection
    bestPartition=communitydetection.best_partition(graph)
    communities=defaultdict(list)
    for node,id in bestPartition.iteritems():
        communities[id].append(node)
    subgraphs=[]
    for nodes in communities.itervalues():
        sg=graph.subgraph(nodes)
        subgraphs.append(sg)
    return subgraphs

def ASFilter(graph, minNumASes):
    ASes=set()
    for node in graph.nodes_iter(data=True):
        if 'color' in node[1] and node[1]['color']==util.IP_COLOR:
            ip=node[0]
            asNum, asOrg = util.getAsnAndOrganisation(ip)
            if asOrg:
                ASes.add(asOrg)
            else:
                ASes.add(asNum)
    if len(ASes)<minNumASes:
        return False
    else:
        return True

def minIPDegreeFilter(graph, minIPDegree=1):
    ips=getIPsInGraph(graph)
    cnt=0
    for ip in ips:
        degree=graph.degree(ip)
        if degree<minIPDegree:
            cnt+=1
            graph.remove_node(ip)

    print 'removed',cnt,'IPs with degree<',minIPDegree

def passesFilters(graph, minNumIPs, maxNumIPs, minNumDomains, minNumASes,
        minIPDistScore, doAnalyzeCommunities=False):
    ips=getIPsInGraph(graph)
    doms=getDomainsInGraph(graph)

    if (len(ips)<minNumIPs or len(ips)>maxNumIPs or
        len(doms)<minNumDomains or not ASFilter(graph, minNumASes) or
        analysis.IPDistScore(ips)<minIPDistScore):
        return False
    elif doAnalyzeCommunities:
        subgraphs=getGraphCommunities(graph)
        numComm=len(subgraphs)
        def f(x):
            return int(round(x/float(numComm)))
            #return int(math.ceil(x/float(numComm)))

        remainingNodes=[]
        for sg in subgraphs:
            if passesFilters(sg, max(f(minNumIPs),2), f(maxNumIPs),
                    max(f(minNumDomains),2), f(minNumASes), minIPDistScore):
                remainingNodes+=sg.nodes()

        remainingSubgraph=graph.subgraph(remainingNodes)
        passes=passesFilters(remainingSubgraph, minNumIPs, maxNumIPs,
                minNumDomains, minNumASes, minIPDistScore)
        if not passes:
            print len(graph),'not passing recursive filter'
        return passes
    else:
        return True

class AppForm(QMainWindow):
    def __init__(self, parent=None):
        QMainWindow.__init__(self, parent)
        self.setWindowTitle('DNSMap')

        """
        init variables, needs to be done before creating the widgets
        """
        self.inputFile=None
        self.suspiciousGraph=nx.Graph()
        self.graphComponents=None
        self.selectedDomain=None
        self.minLikelyBenignShare=0.3
        self.minNumASes=2
        self.minNumIPs=2
        self.maxNumIPs=9999999999
        self.minNumDomains=5
        self.minIPDistScore=0.7
        self.whitelistPatterns=loadWhitelistFromFile('whitelist.txt')
        self.loadTimeBinIndex=1
        self.loadLastSeconds=3600
        self.totDomOcc=dict()
        self.domainDetailsData=defaultdict(list)
        self.doCheckBlacklists=False

        self.create_menu()
        self.create_main_frame()
        self.create_status_bar()

        #self.on_draw()

    def selectInputFile(self):
        path = unicode(QFileDialog.getOpenFileName(self,
                        'Load file', '', ''))
        if path:
            self.inputFile=path
            self.loadSuspicious()

    def loadSuspicious(self):

        start,end=util.getTimeRangeInFile(self.inputFile)
        print 'start,end',start,end
        fromLine=util.seekToTimestamp(self.inputFile,
                    end-(self.loadTimeBinIndex*self.loadLastSeconds))
        toLine=util.seekToTimestamp(self.inputFile,
                    end-((self.loadTimeBinIndex-1)*self.loadLastSeconds), False)
        if fromLine<1:
            fromLine=1
        if toLine<1:
            toLine=np.Inf

        data=util.readSuspiciousFile(self.inputFile, lineNumStart=fromLine,
                lineNumStop=toLine, filterExp=self.whitelistPatterns)

        self.suspiciousGraph=util.buildMappingGraph(data)

        """
        Run over all components in the graph, and remove the ones that don't
        pass the configured filters
        """
        for sg in nx.connected_component_subgraphs(self.suspiciousGraph):
            if not passesFilters(sg, self.minNumIPs, self.maxNumIPs,
                    self.minNumDomains, self.minNumASes, self.minIPDistScore):
                self.suspiciousGraph.remove_nodes_from(sg.nodes())

        domainsTableData=[]
        componentsTableData=[]
        if self.suspiciousGraph:
            """
            keep all those records that contain any of the domains in
            the graph. We need them to be able to show domain details later on.
            """
            domainsInGraph=getDomainsInGraph(self.suspiciousGraph)

            """
            extract suspicious data for all domains shown in graph
            """
            data=[record for record in data if record[1] in domainsInGraph]

            """
            find number of IPs on which each domain name was seen (INCLUDING
            the ones that didn't trigger an alert)
            """
            data.sort(key=lambda x:x[5])
            self.totDomOcc=dict()
            for d in data:
                fqdn=d[1]
                """
                data is sorted, the last occurrence of each domain is therefore
                the one with the highest value of d[5]
                the number of IPs in each line of the suspicious file does not
                include the latest occurrence (i.e., the IP in the line itself)
                -> therefore +1
                """
                self.totDomOcc[fqdn]=d[5]+1

            """
            remove all mappings that were more often considered legitimate than
            suspicious
            """
            cntRemoved=0
            for domain in domainsInGraph:
                numSusp=nx.degree(self.suspiciousGraph, domain)
                numTot=self.totDomOcc[domain]
                #if numTot-numSusp>numSusp:
                if (numSusp/float(numTot))<self.minLikelyBenignShare:
                    print 'likely benign:',str(domain), str(numSusp), str(numTot)
                    self.suspiciousGraph.remove_node(domain)
                    cntRemoved+=1
            print 'removed',str(cntRemoved),'likely benign'

            # FIXME, experimental
            #minIPDegreeFilter(self.suspiciousGraph, 2)

            """
            We changed the graph. Now we have to filter it again, else there'll
            be (usually) lots of tiny fragments.
            """
            for sg in nx.connected_component_subgraphs(self.suspiciousGraph):
                if not passesFilters(sg, self.minNumIPs, self.maxNumIPs,
                        self.minNumDomains, self.minNumASes,
                        self.minIPDistScore, doAnalyzeCommunities=False):
                    self.suspiciousGraph.remove_nodes_from(sg.nodes())

            """
            Set each domain in the graph to 'isMalicious=True'
            """
            for node in self.suspiciousGraph.nodes(data=True):
                if node[1]['color']==util.DOMAIN_COLOR:
                    self.suspiciousGraph.add_node(node[0], {'isMalicious':True})

            """
            Now, find the final scores per graph component
            """
            subgraphs=nx.connected_component_subgraphs(self.suspiciousGraph)
            for sg in subgraphs:

                numEdges=sg.number_of_edges()

                if not numEdges:
                    continue

                numDomainsInSubgraph=0
                numIPsInSubgraph=0
                for node in sg.nodes_iter(data=True):
                    if node[1]['color']==util.DOMAIN_COLOR:
                        compKey=node[0]
                        numDomainsInSubgraph+=1
                    elif node[1]['color']==util.IP_COLOR:
                        numIPsInSubgraph+=1

                """
                find the average of all scores in this subgraph
                """
                avgScore=0.0
                for edge in sg.edges_iter(data=True):
                    score=edge[2]['score']
                    if score>0:
                        avgScore+=score
                avgScore/=numEdges

                """
                """
                componentsTableData.append((compKey, numDomainsInSubgraph,
                    numIPsInSubgraph, avgScore, True))

            """
            keep all those records that contain any of the domains in
            the graph. We need them to be able to show domain details later on.
            """
            domainsInGraph=getDomainsInGraph(self.suspiciousGraph)
            data=[record for record in data if record[1] in domainsInGraph]

            self.domainDetailsData=defaultdict(list)
            for d in data:
                self.domainDetailsData[d[1]].append(d)

            """
            assign overall score to domains: the overall score is the average
            score of all records in which a domain appears
            """
            for domain, records in self.domainDetailsData.iteritems():
                avgDomScore=0.0
                for rec in records:
                    avgDomScore+=rec[4]
                avgDomScore/=len(records)
                self.suspiciousGraph.node[domain]['score']=avgDomScore
                domainsTableData.append((domain, avgDomScore, True))

        """
        update list of suspicious domains
        """
        self.domainsTableModel.updateTableData(domainsTableData)
        self.domainsTable.resizeColumnsToContents()
        self.componentsTableModel.updateTableData(componentsTableData)
        self.componentsTable.resizeColumnsToContents()
        # hide the column that contains the component key. it contains a random
        # domain name from the ones contained in this graph component, and is
        # just used to find the selected graph component in the graph
        #self.componentsTable.setColumnHidden(0, True)

        """
        update status info
        """
        self.updateStatusBar()

        """
        cleanup
        """
        gc.collect()

    def on_about(self):
        msg = """ foobar
        """
        QMessageBox.about(self, "DNSMap", msg.strip())

    def updateStatusBar(self):
        txt=''
        txt+=(str(nx.number_connected_components(self.suspiciousGraph))+
            ' subgraphs; ')
        txt+=(str(len(self.domainDetailsData))+ ' unique domains; ')

        numMaliciousDomains=0
        for sg in nx.connected_component_subgraphs(self.suspiciousGraph):
            for node in sg.nodes_iter(data=True):
                try:
                    color=node[1]['color']
                    isMalicious=node[1]['isMalicious']
                except KeyError:
                    continue
                else:
                    if color==util.DOMAIN_COLOR and isMalicious:
                        numMaliciousDomains+=1
        txt+=str(numMaliciousDomains)+' malicious domains; '

        self.status_text.setText(txt)

    def getCurrentGraph(self):
        if self.toggleHideNotMaliciousDomains.isChecked():
            nodes=[]
            for sg in nx.connected_component_subgraphs(self.suspiciousGraph):
                isMalicious=False
                for node in sg.nodes_iter(data=True):
                    try:
                        isMalicious=node[1]['isMalicious']
                    except KeyError:
                        continue
                    else:
                        break
                if isMalicious:
                    """
                    if at least one domain in this subgraph is malicious, we
                    plot the entire subgraph
                    """
                    nodes+=sg.nodes()
            graph=nx.subgraph(self.suspiciousGraph, nodes)

            """
            FIXME: for some reason the AS nodes have disappeared here, let's
            add them again
            """
            asNodes=defaultdict(list)
            for node in graph.nodes_iter(data=True):
                try:
                    asNodes[node[1]['pid']].append(node[0])
                except KeyError:
                    pass
            for asId,ips in asNodes.iteritems():
                asNum, asOrg =util.getAsnAndOrganisation(ips[0])
                graph.add_node(asId, label=asOrg)
                graph.add_node(asId, {'viz':{
                    'color':{'r':'255','g':'255','b':'0'},
                    'size':str(util.nodeDefaultSize_+2*np.log(len(ips)))}})
        else:
            graph=self.suspiciousGraph
        return graph

    def on_draw(self):
        """
        Redraws the graph in the graph canvas
        """
        graph=self.getCurrentGraph()
        self.showGraph(graph)

    def showGraph(self, graph, doWarn=True):
        """
        clear he axes and redraw the plot anew
        """
        numNodes=len(graph)
        self.axes.clear()
        if numNodes>MAX_NODES_FOR_PLOTTING_GRAPH_:
            self.canvas.draw()
            if doWarn:
                QMessageBox.about(self, "Graph Too Large", "Graph has "
                    +str(numNodes)+" nodes, better use Gephi to draw that")
        else:
            #self.axes.grid(self.grid_cb.isChecked())
            nx.draw_networkx(graph, ax=self.axes)
            self.canvas.draw()

    def saveWhitelist(self):
        oldWhitelistPatterns=self.whitelistPatterns[:]
        self.whitelistPatterns=[]
        text=self.whitelistInput.toPlainText()
        text=str(text)
        whitelistEntries=text.split('\n')
        try:
            for entry in whitelistEntries:
                if entry:
                    r=re.compile(entry)
                    self.whitelistPatterns.append(r)
        except:
            QMessageBox.about(self, 'ERROR', 'could not store whitelist')
            self.whitelistPatterns=oldWhitelistPatterns
        else:
            self.whitelistInput.setText('\n'.join([p.pattern for p in
                self.whitelistPatterns]))

            with open('whitelist.txt', 'w') as f:
                for p in self.whitelistPatterns:
                    f.write(p.pattern+'\n')

    def applyControls(self):
        """
        FIXME, doesn't work
        """
        self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self.status_text.setText('loading ...')
        self.emit(SIGNAL("layoutChanged()"))

        try:
            self.minNumASes=int(self.numASInput.text())
        except ValueError:
            self.numASInput.setText(str(self.minNumASes))

        try:
            self.minNumIPs=int(self.minNumIPInput.text())
        except ValueError:
            self.minNumIPInput.setText(str(self.minNumIPs))

        try:
            self.maxNumIPs=int(self.maxNumIPInput.text())
        except ValueError:
            self.maxNumIPInput.setText(str(self.maxNumIPs))

        try:
            self.minNumDomains=int(self.numDomainsInput.text())
        except ValueError:
            self.numDomainsInput.setText(str(self.minNumDomains))

        try:
            self.minIPDistScore=float(self.minIPDistScoreInput.text())
        except ValueError:
            self.minIPDistScoreInput.setText(str(self.minIPDistScore))

        loadLastSeconds=self.loadLastSecondsInput.text()
        if '*' in loadLastSeconds:
            x=loadLastSeconds.split('*')
            try:
                y=1
                for val in x:
                    y*=int(val)
                self.loadLastSeconds=y
                self.loadLastSecondsInput.setText(str(self.loadLastSeconds))
            except ValueError:
                self.loadLastSecondsInput.setText(str(self.loadLastSeconds))
        else:
            try:
                self.loadLastSeconds=int(self.loadLastSecondsInput.text())
            except ValueError:
                self.loadLastSecondsInput.setText(str(self.loadLastSeconds))

        try:
            self.loadTimeBinIndex=int(self.loadTimeBinIndexInput.text())
        except ValueError:
            self.loadTimeBinIndexInput.setText(str(self.loadTimeBinIndexInput))

        if self.inputFile:
            """
            reload the input file with the new settings
            """
            print 'reloading',self.inputFile
            self.loadSuspicious()

    def showDetailsForDomain(self, domain):
        occurrences=self.domainDetailsData[domain]
        occurrences.sort(key=lambda x:x[0])
        try:
            lastTimestamp=occurrences[-1][0]
        except IndexError:
            print 'error'
            print occurrences
            return

        """
        find graph component for <domain>
        """
        graphComponent=nx.node_connected_component(self.suspiciousGraph,
                domain)
        sg=self.suspiciousGraph.subgraph(graphComponent)

        """
        find FQDNs in this graph component
        """
        fqdnsInComp=[n[0] for n in sg.nodes_iter(data=True) if
                n[1]['color']==util.DOMAIN_COLOR]
        numDomainsInComp=len(fqdnsInComp)

        """
        find IPs in this graph component
        """
        ipsInComp=[netaddr.IPAddress(n[0]) for n in sg.nodes_iter(data=True) if
            n[1]['color']==util.IP_COLOR]
        ipsInComp.sort()
        ipsInComp=[str(ip) for ip in ipsInComp]

        """
        find autonomous systems for these IPs
        """
        ASes=set()
        for ip in ipsInComp:
            ASes.add(str(util.getAsnAndOrganisation(str(ip))))

        """
        find median distance between IP addresses in this component
        """
        #medianIPDist=analysis.IPDistMedian(ipsInComp)
        medianIPDist=analysis.IPDistScore(ipsInComp)

#FIXME
        print 'last byte IP entropy', analysis.ipLastByteEntropy(ipsInComp)

        """
        get node with maximum betweenness value
        """
        #nodesBetweenness=analysis.nodeBetweenness(sg, 'score')
        #nodesBetweenness=nodesBetweenness.items()
        #nodesBetweenness.sort(key=lambda x:x[1])
        #IPNodesBetweenness=[(node,b) for (node,b) in nodesBetweenness if
                #sg.node[node]['color']==util.IP_COLOR]
        #fqdnNodesBetweenness=[(node,b) for (node,b) in nodesBetweenness if
        #        sg.node[node]['color']==util.DOMAIN_COLOR]

        IPNodesBetweenness=analysis.NodeBetweennessSubset(sg, ipsInComp,
                'score')
        IPNodesBetweenness=IPNodesBetweenness.items()
        IPNodesBetweenness.sort(key=lambda x:x[1])

        fqdnNodesBetweenness=analysis.NodeBetweennessSubset(sg, fqdnsInComp,
                'score')
        fqdnNodesBetweenness=fqdnNodesBetweenness.items()
        fqdnNodesBetweenness.sort(key=lambda x:x[1])

        for node in IPNodesBetweenness:
            topIPBetweennessNode=IPNodesBetweenness[-1]
            if node[0] in ipsInComp:
                break

        for node in fqdnNodesBetweenness:
            topFqdnBetweennessNode=fqdnNodesBetweenness[-1]
            if node[0] in fqdnsInComp:
            break

        """
        Create domain details string
        """
        txt='<b>'+domain+'</b><br>'
        txt+=str(numDomainsInComp)+' domains in this subgraph<br>'
        txt+=str(len(ipsInComp))+' IPs in this subgraph<br>'
        txt+='Appears suspicious on #IPs: '+str(len(occurrences))+'<br>'
        txt+='Active on #IPs: '+str(self.totDomOcc[domain])+'<br>'
        txt+='Average score: '+str(np.mean([rec[4] for rec in
            occurrences]))+'<br>'
        lastTimePretty=time.strftime("%d.%m.%Y -- %H:%M", time.gmtime(lastTimestamp))
        txt+='Last time seen: '+str(lastTimePretty)+'<br>'
        txt+='IP distance score: '+str(medianIPDist)+'<br>'
        txt+='Max. IP Node Betweenness: '+str(topIPBetweennessNode)+'<br>'
        txt+='Max. FQDN Node Betweenness: '+str(topFqdnBetweennessNode)+'<br>'
        txt+='top 2-LD suffix: '+str(util.getTopDomainSuffix(fqdnsInComp, 2))+'<br>'
        txt+='top 3-LD suffix: '+str(util.getTopDomainSuffix(fqdnsInComp, 3))+'<br>'
        txt+=str(len(ASes))+' ASes: '+', '.join(ASes)+'<br>'
        txt+='IPs: '+', '.join(ipsInComp)+'<br>'
        txt+='FQDNs: '+', '.join(fqdnsInComp)+'<br>'
        self.domainDetails.setText(txt)
        self.selectedDomain=domain

        """
        update 'isMalicious' checkbox
        """
        isMalicious=(True and self.suspiciousGraph.node[domain]['isMalicious'])
        self.componentCheckbox.setChecked(isMalicious)

    def doWhitelistDomain(self):
        domain=self.selectedDomain
        pattern='^'+domain+'$'
        pattern=pattern.replace('.', '\.')
        r=re.compile(pattern)
        self.whitelistPatterns.append(r)
        self.whitelistInput.setText('\n'.join([r.pattern for r in
            self.whitelistPatterns]))

    def domainsTableRecordSelect(self, mi):
        """
        Updates the domain details widget with data selected in domain list
        """
        row = self.domainsTableModel.arraydata[mi.row()]
        domain=row[0]

        self.showDetailsForDomain(domain)

        """
        plot graph component
        """
        graphComponent=nx.node_connected_component(self.suspiciousGraph,
                domain)
        sg=self.suspiciousGraph.subgraph(graphComponent)
        self.showGraph(sg, doWarn=False)

    def componentsTableRecordSelect(self, mi):
        row = self.componentsTableModel.arraydata[mi.row()]
        domain=row[0]

        self.showDetailsForDomain(domain)

        """
        find graph component for <domain>
        """
        graphComponent=nx.node_connected_component(self.suspiciousGraph,
                domain)
        sg=self.suspiciousGraph.subgraph(graphComponent)

        """
        plot graph component
        """
        self.showGraph(sg, doWarn=False)

    def toggleCheckBlacklist(self, state):
        if state==Qt.Checked:
            self.doCheckBlacklists=True
        elif state==Qt.Unchecked:
            self.doCheckBlacklists=False

    def toggleComponentSuspicious(self, state):
        if not self.selectedDomain:
            return

        graphComponent=nx.node_connected_component(self.suspiciousGraph,
                self.selectedDomain)
        for domain in graphComponent:
            node=self.suspiciousGraph.node[domain]

            if state==Qt.Checked:
                node['isMalicious']=True
                self.componentsTableModel.setComponentMalicious(domain, True)
            elif state==Qt.Unchecked:
                node['isMalicious']=False
                self.componentsTableModel.setComponentMalicious(domain, False)

        """
        update table data
        """
        if self.toggleHideNotMaliciousDomains.isChecked():
            self.toggleHideNonMalicious(Qt.Checked)
        else:
            self.toggleHideNonMalicious(Qt.Unchecked)

        self.updateStatusBar()

    def toggleHideNonMalicious(self, state):
        domainsTableData=[]

        for node in self.suspiciousGraph.nodes_iter(data=True):
            if node[1]['color']==util.DOMAIN_COLOR:
                isMalicious = node[1]['isMalicious']
                if state == Qt.Checked:
                    if not isMalicious:
                        continue
                domainsTableData.append((node[0], node[1]['score'],
                    isMalicious))

        """
        update table data
        """
        self.domainsTableModel.updateTableData(domainsTableData)

    def exportGraph(self):
        path = unicode(QFileDialog.getSaveFileName(self,
                        'Save graph', '', ''))
        if path:
            if not path.endswith('.gexf'):
                path+='.gexf'
            graph=self.getCurrentGraph()
            graph=graph.copy()
            util.createASHierarchy(graph, 2)
            nx.write_gexf(graph, path)

    def exportMalicious(self):
        """
        writes all domains that have the 'isMalicious' flag, and all the IPs
        that these domains are mapping to, to a file
        """
        path = unicode(QFileDialog.getSaveFileName(self,
                        'Save malicious', '', ''))
        if path:
            maliciousDomains=[node[0] for node in
                    self.suspiciousGraph.nodes_iter(data=True) if
                    node[1]['color']==util.DOMAIN_COLOR and
                    node[1]['isMalicious']]

            maliciousIPs=set()
            for md in maliciousDomains:
                try:
                    records=self.domainDetailsData[md]
                except KeyError:
                    pass
                else:
                    for rec in records:
                        maliciousIPs.add(rec[2])

            f=open(path, 'w')
            for md in maliciousDomains:
                score=self.suspiciousGraph.node[md]['score']
                f.write(' '.join([md, str(score)])+'\n')
            for mip in maliciousIPs:
                f.write(mip+'\n')
            f.close()

    def create_main_frame(self):
        self.main_frame = QWidget()
        self.setWindowIcon(QIcon('data/dnsmap_logo.png'))

        """
        Create tabs for domains table and graph components table
        """
        tabWidget = QTabWidget()
        domainsTab = QWidget()
        componentsTab = QWidget()
        whitelistTab = QWidget()
        tabWidget.addTab(domainsTab, "Domains")
        tabWidget.addTab(componentsTab, "Components")
        tabWidget.addTab(whitelistTab, "Whitelist")

        """
        create table to show malicious components
        """
        self.componentsTable = QTableView()

        # set the table model
        header = ['key', '#domains', '#IPs', 'component score', 'isMalicious']
        tm = ComponentsTableModel([], header, self)
        self.componentsTable.setModel(tm)
        self.componentsTableModel=tm

        # set the minimum size
        self.componentsTable.setMinimumSize(400, 300)

        # set the font
        font = QFont("Courier New", 9)
        self.componentsTable.setFont(font)

        # hide vertical header
        vh = self.componentsTable.verticalHeader()
        vh.setVisible(False)

        # set horizontal header properties
        hh = self.componentsTable.horizontalHeader()
        hh.setStretchLastSection(True)

        # set column width to fit contents
        self.componentsTable.resizeColumnsToContents()

        # enable sorting
        self.componentsTable.setSortingEnabled(True)
        self.connect(self.componentsTable, SIGNAL("doubleClicked(QModelIndex)"),
                self.componentsTableRecordSelect)

        """
        create table to show malicious domains
        """
        self.domainsTable = QTableView()

        # set the table model
        header = ['domain', 'score', 'isMalicious']
        tm = DomainsTableModel([], header, self)
        self.domainsTable.setModel(tm)
        self.domainsTableModel=tm

        # set the minimum size
        self.domainsTable.setMinimumSize(400, 300)

        # set the font
        font = QFont("Courier New", 9)
        self.domainsTable.setFont(font)

        # hide vertical header
        vh = self.domainsTable.verticalHeader()
        vh.setVisible(False)

        # set horizontal header properties
        hh = self.domainsTable.horizontalHeader()
        hh.setStretchLastSection(True)

        # set column width to fit contents
        self.domainsTable.resizeColumnsToContents()

        # set row height
#        nrows = len(self.tabledata)
#        for row in xrange(nrows):
#            self.domainsTable.setRowHeight(row, 18)

        # enable sorting
        self.domainsTable.setSortingEnabled(True)

        self.connect(self.domainsTable, SIGNAL("doubleClicked(QModelIndex)"),
                self.domainsTableRecordSelect)

        """
        Create whitelist editor
        """
        self.whitelistInput=QTextEdit()
#FIXME
        self.whitelistInput.setText('\n'.join([r.pattern for r in
            self.whitelistPatterns]))
        self.whitelistSaveButton = QPushButton('Save Whitelist')
        self.whitelistSaveButton.clicked.connect(self.saveWhitelist)

        """
        Create domain details widget
        """
        self.domainDetails=QTextEdit()
        self.domainDetails.setReadOnly(True)

        """
        Create interactive checkbox to label graph components good/bad
        """
        self.componentCheckbox=QCheckBox()
        self.componentCheckbox.setText('Malicious Component')
        self.connect(self.componentCheckbox, SIGNAL("stateChanged(int)"),
                self.toggleComponentSuspicious)

        """
        """
        self.checkBlacklistCheckbox=QCheckBox()
        self.checkBlacklistCheckbox.setChecked(self.doCheckBlacklists)
        self.checkBlacklistCheckbox.setText('Check Blacklists')
        self.connect(self.checkBlacklistCheckbox, SIGNAL("stateChanged(int)"),
                self.toggleCheckBlacklist)

        """
        add button for whitelisting selected domains
        """
        self.whitelistButton = QPushButton('Whitelist')
        self.whitelistButton.clicked.connect(self.doWhitelistDomain)

        """
        Create parameter controls for graph analysis
        """
        self.numASInput = QLineEdit(str(self.minNumASes))
        self.minNumIPInput = QLineEdit(str(self.minNumIPs))
        self.maxNumIPInput = QLineEdit(str(self.maxNumIPs))
        self.numDomainsInput = QLineEdit(str(self.minNumDomains))
        self.minIPDistScoreInput = QLineEdit(str(self.minIPDistScore))
        self.loadTimeBinIndexInput = QLineEdit(str(self.loadTimeBinIndex))
        self.loadLastSecondsInput = QLineEdit(str(self.loadLastSeconds))
        self.controlsApplyButton = QPushButton('Reload')
        self.controlsApplyButton.clicked.connect(self.applyControls)

        """
        Create the mpl Figure and FigCanvas objects.
        5x4 inches, 100 dots-per-inch
        """
        self.dpi = 100
        #self.fig = Figure((5.0, 4.0), dpi=self.dpi)
        self.fig = figure(figsize=(5.0, 4.0), dpi=self.dpi)
        self.canvas = FigureCanvas(self.fig)
        self.canvas.setParent(self.main_frame)

        # Since we have only one plot, we can use add_axes
        # instead of add_subplot, but then the subplot
        # configuration tool in the navigation toolbar wouldn't
        # work.
        #
        self.axes = self.fig.add_subplot(111)

        # don't show axis
        self.axes.get_xaxis().set_visible(False)
        self.axes.get_yaxis().set_visible(False)

        # Bind the 'pick' event for clicking on one of the bars
        #
        #self.canvas.mpl_connect('pick_event', self.on_pick)

        # Create the navigation toolbar, tied to the canvas
        #
        self.mpl_toolbar = NavigationToolbar(self.canvas, self.main_frame)

        # Other GUI controls
        # 
        #self.textbox = QLineEdit()
        #self.textbox.setMinimumWidth(200)
        #self.connect(self.textbox, SIGNAL('editingFinished ()'), self.on_draw)

        self.draw_button = QPushButton("Plot Graph")
        self.connect(self.draw_button, SIGNAL('clicked()'), self.on_draw)

        self.export_graph_button = QPushButton("Export Graph")
        self.connect(self.export_graph_button, SIGNAL('clicked()'),
                self.exportGraph)

        self.exportMaliciousButton = QPushButton('Export Malicious')
        self.connect(self.exportMaliciousButton, SIGNAL('clicked()'),
                self.exportMalicious)

        self.toggleHideNotMaliciousDomains = QCheckBox('Hide Non-Malicious Domains')
        self.connect(self.toggleHideNotMaliciousDomains, SIGNAL('stateChanged(int)'),
                self.toggleHideNonMalicious)

        #self.grid_cb = QCheckBox("Show &Grid")
        #self.grid_cb.setChecked(False)
        #self.connect(self.grid_cb, SIGNAL('stateChanged(int)'), self.on_draw)

        #slider_label = QLabel('Bar width (%):')
        #self.slider = QSlider(Qt.Horizontal)
        #self.slider.setRange(1, 100)
        #self.slider.setValue(20)
        #self.slider.setTracking(True)
        #self.slider.setTickPosition(QSlider.TicksBothSides)
        #self.connect(self.slider, SIGNAL('valueChanged(int)'), self.on_draw)


        """
        Create tabbed layout for domains/components list + details view
        """
        domainPanel = QVBoxLayout(domainsTab)
        componentsPanel = QVBoxLayout(componentsTab)
        whitelistPanel = QVBoxLayout(whitelistTab)
        domainPanel.addWidget(self.domainsTable)
        componentsPanel.addWidget(self.componentsTable)
        whitelistPanel.addWidget(self.whitelistInput)

        tabAndDetailsPanel=QVBoxLayout()
        tabAndDetailsPanel.addWidget(tabWidget)
        tabAndDetailsPanel.addWidget(self.componentCheckbox)
        tabAndDetailsPanel.addWidget(self.toggleHideNotMaliciousDomains)
        tabAndDetailsPanel.addWidget(self.checkBlacklistCheckbox)
        tabAndDetailsPanel.addWidget(self.whitelistButton)
        tabAndDetailsPanel.addWidget(self.domainDetails)

        """
        Create layout for graph canvas + plotting controls
        """
        graphPanel = QVBoxLayout()
        graphPanel.addWidget(self.canvas)
        graphPanel.addWidget(self.mpl_toolbar)

        """
        Create layout of control panel
        """
        controlPanel=QVBoxLayout()
        controlPanel.addWidget(QLabel('min. ASes per component'))
        controlPanel.addWidget(self.numASInput)
        controlPanel.addWidget(QLabel('min. IPs per component'))
        controlPanel.addWidget(self.minNumIPInput)
        controlPanel.addWidget(QLabel('max. IPs per component'))
        controlPanel.addWidget(self.maxNumIPInput)
        controlPanel.addWidget(QLabel('min. FQDNs per component'))
        controlPanel.addWidget(self.numDomainsInput)
        controlPanel.addWidget(QLabel('min. IPDistScore per component'))
        controlPanel.addWidget(self.minIPDistScoreInput)
        controlPanel.addWidget(QLabel('timeslot index; 1=last'))
        controlPanel.addWidget(self.loadTimeBinIndexInput)
        controlPanel.addWidget(QLabel('timeslot length [seconds]; e.g. 60*60*24'))
        controlPanel.addWidget(self.loadLastSecondsInput)
        controlPanel.addWidget(self.controlsApplyButton)

        """
        Create Layout to hold buttons
        """
        buttonsLayout = QHBoxLayout()
        for w in [self.draw_button, self.export_graph_button,
                self.exportMaliciousButton]:
            buttonsLayout.addWidget(w)
            buttonsLayout.setAlignment(w, Qt.AlignVCenter)

        """
        add whitelist-specific controls
        """
        whitelistPanel.addWidget(self.whitelistSaveButton)

        """
        auxiliary layouts to combine control panel + buttons + graph canvas
        """
        auxLayout = QHBoxLayout()
        auxLayout.addLayout(controlPanel)
        auxLayout.addLayout(buttonsLayout)
        auxLayout2=QVBoxLayout()
        auxLayout2.addLayout(graphPanel)
        auxLayout2.addLayout(auxLayout)

        """
        Create main layout, bringing everything together
        """
        mainLayout = QHBoxLayout()
        mainLayout.addLayout(tabAndDetailsPanel)
        mainLayout.addLayout(auxLayout2)

        self.main_frame.setLayout(mainLayout)
        self.setCentralWidget(self.main_frame)

    def create_status_bar(self):
        self.status_text = QLabel()
        self.statusBar().addWidget(self.status_text, 1)

    def create_menu(self):
        self.file_menu = self.menuBar().addMenu("&File")

        load_file_action = self.create_action("&Load Suspicious",
            shortcut="Ctrl+L", slot=self.selectInputFile,
            tip="Load suspicious DNS mappings from txt file")
        quit_action = self.create_action("&Quit", slot=self.close,
            shortcut="Ctrl+Q", tip="Close the application")

        self.add_actions(self.file_menu,
            (load_file_action, None, quit_action))

        self.help_menu = self.menuBar().addMenu("&Help")
        about_action = self.create_action("&About",
            shortcut='F1', slot=self.on_about,
            tip='About the demo')

        self.add_actions(self.help_menu, (about_action,))

    def add_actions(self, target, actions):
        for action in actions:
            if action is None:
                target.addSeparator()
            else:
                target.addAction(action)

    def create_action(  self, text, slot=None, shortcut=None,
                        icon=None, tip=None, checkable=False,
                        signal="triggered()"):
        action = QAction(text, self)
        if icon is not None:
            action.setIcon(QIcon(":/%s.png" % icon))
        if shortcut is not None:
            action.setShortcut(shortcut)
        if tip is not None:
            action.setToolTip(tip)
            action.setStatusTip(tip)
        if slot is not None:
            self.connect(action, SIGNAL(signal), slot)
        if checkable:
            action.setCheckable(True)
        return action


def main():
    app = QApplication(sys.argv)
    form = AppForm()
    form.show()
    app.exec_()

if __name__ == "__main__":
    main()

