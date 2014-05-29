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

# (c) Hugh Bothwell
# http://stackoverflow.com/a/4923529

from os import path
import urllib2

class TldMatcher(object):
    # use class vars for lazy loading
    MASTERURL = "http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1"
    MASTERFILE = 'data/effective_tld_names.dat'
    TLDS = None

    @classmethod
    def fetchTlds(cls, url=None):
        url = url or cls.MASTERURL

        # grab master list
        print 'fetching TLD list from server ...'
        lines = urllib2.urlopen(url).readlines()

        f = open(cls.MASTERFILE, 'w')
        f.writelines(lines)
        f.close()

    @classmethod
    def loadTlds(cls):
        f = open(cls.MASTERFILE, 'r')
        lines = f.readlines()
        f.close()

        # strip comments and blank lines
        lines = [ln for ln in (ln.strip() for ln in lines) if len(ln) and ln[:2]!='//']

        cls.TLDS = set(lines)

    def __init__(self):

        if path.exists(TldMatcher.MASTERFILE):
            TldMatcher.loadTlds()

        if TldMatcher.TLDS is None:
            TldMatcher.fetchTlds()
            TldMatcher.loadTlds()

    def getTld(self, url):
        best_match = None
        chunks = url.split('.')

        for start in range(len(chunks)-1, -1, -1):
            test = '.'.join(chunks[start:])
            startest = '.'.join(['*']+chunks[start+1:])

            if test in TldMatcher.TLDS or startest in TldMatcher.TLDS:
                best_match = test

        return best_match

    def get2ld(self, url):
        urls = url.split('.')
        tlds = self.getTld(url).split('.')
        return urls[-1 - len(tlds)]


def test_TldMatcher():
    matcher = TldMatcher()

    test_urls = [
        'site.co.uk',
        'site.com',
        'site.me.uk',
        'site.jpn.com',
        'site.org.uk',
        'site.it'
    ]

    errors = 0
    for u in test_urls:
        res = matcher.get2ld(u)
        if res != 'site':
            print "Error: found '{0}', should be 'site'".format(res)
            errors += 1

    if errors==0:
        print "Passed!"
    return (errors==0)

