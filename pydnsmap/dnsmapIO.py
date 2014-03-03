import sys
import time
import Queue
import multiprocessing as mp
import socket
import base64
import re
import sqlite3
from os.path import getsize as file_getsize
import gzip
import pcap
import dpkt
from netaddr import IPAddress
import progressbar
#from google.protobuf.message import DecodeError

INPUTMODE_FIFO=1
INPUTMODE_PROTOBUF=2
INPUTMODE_PCAP_FILE=3
INPUTMODE_PCAP_IF=4

DNS_RECORD_TYPES_={
    1: 'DNS_A',
    2: 'DNS_NS',
    3: 'DNS_MD',
    4: 'DNS_MF',
    5: 'DNS_CNAME',
    6: 'DNS_SOA',
    7: 'DNS_MB',
    8: 'DNS_MG',
    9: 'DNS_MR',
    10: 'DNS_NULL_RR',
    11: 'DNS_WKS',
    12: 'DNS_PTR',
    13: 'DNS_HINFO',
    14: 'DNS_MINFO',
    15: 'DNS_MX',
    16: 'DNS_TXT',
    17: 'DNS_RP',
    18: 'DNS_AFSDB',
    19: 'DNS_X25',
    20: 'DNS_ISDN',
    21: 'DNS_RT',
    22: 'DNS_NSAP',
    23: 'DNS_NSAP_PTR',
    24: 'DNS_SIG',
    25: 'DNS_KEY',
    26: 'DNS_PX',
    27: 'DNS_GPOS',
    28: 'DNS_AAAA',
    29: 'DNS_LOC',
    30: 'DNS_NXT',
    31: 'DNS_EID',
    32: 'DNS_NIMLOC',
    33: 'DNS_SRV',
    34: 'DNS_ATMA',
    35: 'DNS_NAPTR',
    36: 'DNS_KX',
    37: 'DNS_CERT',
    38: 'DNS_A6',
    39: 'DNS_DNAME',
    40: 'DNS_SINK',
    41: 'DNS_OPT',
    42: 'DNS_APL',
    43: 'DNS_DS',
    44: 'DNS_SSHFP',
    45: 'DNS_IPSECKEY',
    46: 'DNS_RRSIG',
    47: 'DNS_NSEC',
    48: 'DNS_DNSKEY',
    49: 'DNS_DHCID',
    50: 'DNS_NSEC3',
    51: 'DNS_NSEC3PARAM',
    55: 'DNS_HIP',
    56: 'DNS_NINFO',
    57: 'DNS_RKEY',
    99: 'DNS_SPF',
    100: 'DNS_UINFO',
    101: 'DNS_UID',
    102: 'DNS_GID',
    103: 'DNS_UNSPEC',
    249: 'DNS_TKEY',
    250: 'DNS_TSIG',
    251: 'DNS_IXFR',
    252: 'DNS_AXFR',
    253: 'DNS_MAILB',
    254: 'DNS_MAILA',
    255: 'DNS_ALL',
    32768: 'DNS_TA',
    32769: 'DNS_DLV',
    65535: 'DNS_UNKNOWN'
}

def checkMapping(dic, dname, ips):
    newIps = set()
    newMapping = False
    if dname in dic: #partially or totally mapped?
        for ip in ips:
            if ip in dic[dname]: #totally mapped
                continue
            else:
                newIps.add(ip) #partially mapped --> new mapping
                dic[dname].add(ip)
                newMapping = True
        if newMapping:
            return newIps
        else:
            return None
    else: #new mapping
        newIps = set(ips)
        dic[dname] = newIps
        return newIps

def dumpToDatabase(curs, timestamp, fqdn, ips, clientID, table):
    for ip in ips:
        sql = "INSERT INTO %s" % table
        sql += " (timestamp, fqdn, ip, clientID) values (%s, %s, %s, %s)"
        curs.execute(sql, (timestamp, fqdn, int(ip), clientID))

        # alternative, works for sqlite only
        #curs.execute("INSERT INTO dnsmappings(timestamp, fqdn, ip) VALUES(?,?,?)", (timestamp, fqdn, int(ip)))

def pcapReader(q, exitSignal, infile=None, interface=None, thrsh=0):

    if not infile and not interface:
        # FIXME: write warning here
        return

    if infile:
        pc=pcap.pcapObject()
        try:
            pc.open_offline(infile)
        except IOError:
            #log("could not open pcap interface "+str(input_interface)+"\n")
            pass

    if interface:
        pc=pcap.pcapObject()
        try:
            #pc.open_live(interface, snaplen, promisc, read_timeout)
            pc.open_live(interface, 1600, 0, 100)
        except IOError:
            #log("could not open pcap interface "+str(input_interface)+"\n")
            pass
        except Exception:
            # most likely we got no permission to open the interface
            sys.stderr.write('could not open interface. insufficient '
                'permissions?\n')
            q.put(None)
            return

    pc.setfilter('udp', 0, 0)
    basets=0
    newMappings=dict()

    while True:
        if exitSignal.is_set():
            break

        try:
            packet=pc.next()
            if not packet:
                if infile:
                    # end of file
                    break
                elif interface:
                    # read timeout
                    continue

            payload=packet[1]
            timestamp=int(packet[2])

            # make sure we are dealing with IP traffic
            # ref: http://www.iana.org/assignments/ethernet-numbers
            try: eth = dpkt.ethernet.Ethernet(payload)
            except: continue
            if eth.type != 2048: continue

            # make sure we are dealing with UDP
            # ref: http://www.iana.org/assignments/protocol-numbers/
            try: ip = eth.data
            except: continue
            if ip.p != 17: continue

            # filter on UDP assigned ports for DNS
            # ref: http://www.iana.org/assignments/port-numbers
            try: udp = ip.data
            except: continue
            if udp.sport != 53 and udp.dport != 53: continue

            # make the dns object out of the udp data and check for it being a RR (answer)
            # and for opcode QUERY (I know, counter-intuitive)
            try: dns = dpkt.dns.DNS(udp.data)
            except: continue
            if dns.qr != dpkt.dns.DNS_R: continue
            if dns.opcode != dpkt.dns.DNS_QUERY: continue
            if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
            if len(dns.an) < 1: continue
            if len(dns.qd) == 0: continue

            aRecords=set()
            queriedName=dns.qd[0].name

            if not '.' in queriedName:
                continue

            #lastCname=queriedName
            for answer in dns.an:
                """
                FIXME: this doesn't work for multiple queries in one DNS packet
                """
                #if answer.type == dpkt.dns.DNS_CNAME:
                #    lastCname=answer.cname
                if answer.type == dpkt.dns.DNS_A:
                    ip=socket.inet_ntoa(answer.rdata)
                    try:
                        addr=IPAddress(ip)
                    except netaddr.AddrFormatError:
                        continue
                    else:
                        if (addr.is_unicast() and
                            not addr.is_private() and
                            not addr.is_reserved() and
                            not addr.is_loopback()):
                            aRecords.add(addr)

            if thrsh:
                if (timestamp-basets) > thrsh:
                    basets = timestamp
                    newMappings.clear()

                newIps = checkMapping(newMappings, queriedName, aRecords)
                aRecords=newIps

            if not aRecords:
                continue

            data = ((queriedName, ip.dst, aRecords), timestamp)
            queued=False
            while not queued:
                try:
                    q.put_nowait(data)
                except Queue.Full:
                    # we saturated the queue, let's give the reading
                    # process some time to empty it again, where we don't
                    # try to put something in the queue and thereby lock it
                    # continuously
                    time.sleep(sleeptime)

                    if q.empty():
                        sleeptime*=0.5
                    elif q.qsize() >= q._maxsize:
                        sleeptime*=2
                        if sleeptime>maxSleeptime:
                            sleeptime=maxSleeptime
                else:
                    queued=True

        except KeyboardInterrupt:
            break

    """
    send shutdown signal
    """
    q.put(None)


def protobufReader(infile, q, exitSignal, thrsh=0, useProgressbar=True):
    """
    not implemented
    """
    pass

def fifoReader(infile, q, exitSignal):
    sleeptime=0.5
    maxSleeptime=1.0

    while True:
        try:
            if exitSignal.is_set(): break

            line=infile.readline()

            if not line:
                time.sleep(1)
                continue

            if line=='ENDOFFILE':
                break

            try:
                spl=line.split()
                timestamp, queriedName, clientID, ipv4 = spl
            except:
                continue
            else:
                if not '.' in queriedName:
                    continue
                try:
                    addr=IPAddress(ipv4)
                except netaddr.AddrFormatError:
                    continue
                else:
                    if (addr.is_unicast() and
                        not addr.is_private() and
                        not addr.is_reserved() and
                        not addr.is_loopback()):

                        try:
                            timestamp=int(timestamp)
                        except ValueError:
                            continue
                        else:
                            data = ((queriedName, clientID, [addr]),
                                    timestamp)
                            queued=False
                            while not queued:
                                try:
                                    q.put_nowait(data)
                                except Queue.Full:
                                    # we saturated the queue, let's give the reading
                                    # process some time to empty it again, where we don't
                                    # try to put something in the queue and thereby lock it
                                    # continuously
                                    time.sleep(sleeptime)

                                    if q.empty():
                                        sleeptime*=0.5
                                    elif q.qsize() >= q._maxsize:
                                        sleeptime*=2
                                        if sleeptime>maxSleeptime:
                                            sleeptime=maxSleeptime
                                else:
                                    queued=True

        except KeyboardInterrupt:
            break

    q.put(None)

def fakeMappingGenerator(filename):
    with open(filename, 'r') as f:
        for line in f:
            """
            expect format <timestamp> <fqdn> <IP>
            """
            sline=line.split()
            timestamp=int(sline[0])
            fqdn=sline[1]
            ip=IPAddress(sline[2])
            yield (timestamp, fqdn, ip)

class recGen(object):

    def __init__(self, inputSource, mode, gzippedInput=False, thrsh=0,
        useProgressbar=True, dbfile=None, dbserver=None):
        """
        mode:
        1: read from fifo
        2: read from protobuf file
        3: read from pcap file
        4: read from pcap interface

        dbfile: a filename to create an SQLite database containing the
        processed NOERROR queries
        dbserver: a tuple (serverIP, dbuser, dbpass, dbname) specifying a MYSQL
        database for storing the processed NOERROR queries

        returns (ticket_dns object, timestamp)
        if thrsh==0: don't filter
        else: filter every thrsh seconds
        """
        self.mode=mode
        self.inputSource=inputSource
        self.gzippedInput=gzippedInput
        self.thrsh=thrsh
        self.useProgressbar=useProgressbar
        self.dbfile=dbfile
        self.dbserver=dbserver
        self.dbtable='dnsmappings'
        self.infile=None

    def __enter__(self):
        if (self.mode==INPUTMODE_FIFO or self.mode==INPUTMODE_PROTOBUF or
                self.mode==INPUTMODE_PCAP_FILE):
            if self.inputSource=='-':
                self.infile = sys.stdin
            else:
                if self.gzippedInput:
                    self.infile=gzip.GzipFile(self.inputSource)
                else:
                    self.infile = open(self.inputSource, 'rb')

        if self.dbfile:
            self.conn=sqlite3.connect(self.dbfile)
            self.curs=self.conn.cursor()
            self.curs.execute("CREATE TABLE dnsmappings(Id BIGINT PRIMARY KEY AUTOINCREMENT, timestamp INT, fqdn TEXT, ip INT, clientID INT)")
            self.curs.execute("CREATE INDEX ip_idx ON dnsmappings (fqdn);")
            self.conn.commit()
        elif self.dbserver:
            import MySQLdb
            serverIP,dbuser,dbpass,dbname=self.dbserver
            self.conn = MySQLdb.connect(serverIP,dbuser,dbpass,dbname)
            self.curs=self.conn.cursor()
            self.curs.execute("CREATE TABLE dnsmappings(Id BIGINT AUTO_INCREMENT, timestamp int unsigned, fqdn varchar(255), ip int unsigned, clientID int unsigned, PRIMARY KEY (Id), INDEX(fqdn))")
            self.conn.commit()

        return self

    def __exit__(self, *exc_info):
        if (self.mode==INPUTMODE_FIFO or self.mode==INPUTMODE_PROTOBUF or
            self.mode==INPUTMODE_PCAP_FILE) and self.infile!=sys.stdin:
            self.infile.close()

        if self.dbfile or self.dbserver:
            self.conn.commit()
            self.conn.close()

    def __iter__(self):
        return self

    def next(self):
        return self.nnext()

    def nnext(self):

        q = mp.Queue(10000)
        exitSignal = mp.Event()

        if self.mode==INPUTMODE_FIFO:
            proc = mp.Process(target=fifoReader, args=(self.infile, q, exitSignal))
        elif self.mode==INPUTMODE_PROTOBUF:
            if self.gzippedInput:
                proc = mp.Process(target=protobufReader, args=(self.infile, q, exitSignal,
                    self.thrsh, False))
            else:
                proc = mp.Process(target=protobufReader, args=(self.infile, q, exitSignal,
                    self.thrsh, self.useProgressbar))
        elif self.ode==INPUTMODE_PCAP_FILE:
            proc = mp.Process(target=pcapReader, args=(q, exitSignal,),
                kwargs={'thrsh':self.thrsh, 'infile':self.inputSource})
        elif self.mode==INPUTMODE_PCAP_IF:
            proc = mp.Process(target=pcapReader, args=(q, exitSignal,),
                kwargs={'thrsh':self.thrsh, 'interface':self.inputSource})

        proc.daemon = True
        proc.start()

        while True:
            try:
                try:
                    data = q.get(timeout=60) # this is the only consumer and the queue is not empty, so it returns the next item immediately
                except Queue.Empty:
                    """
                    read timeout: return an empty record to keep the DNSMap going
                    """
                    yield ((None, None, []), None)
                    continue
                else:
                    if data == None:
                        break
                    else:

                        if self.dbfile or self.dbserver:
                            (queriedName, clientID, ips), timestamp = data
                            dumpToDatabase(self.curs, timestamp, queriedName,
                                    ips, clientID, self.dbtable)

                        yield data
            except KeyboardInterrupt:
                """
                kill the reader process
                """
                exitSignal.set()

def recordTypeToStr(rec_type):
    try:
        return DNS_RECORD_TYPES_[rec_type]
    except IndexError:
        return 'UNKNOWN'

if __name__ == "__main__":
    import sys
    r=recGen(mode=INPUTMODE_PROTOBUF, inputSource=sys.argv[1],
            thrsh=0, useProgressbar=False, gzippedInput=True)
    for record in r:
        for ip in record[0][2]:
            print record[1], record[0][0], str(ip)
