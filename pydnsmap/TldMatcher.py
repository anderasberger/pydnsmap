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

