import bisect
from Queue import deque

class dataObj:
    ''' data wrapper '''
    #CORE, BORDER, NOISE = 0, 1, 2
    __slots__=['data','visited','assigned']

    def __init__(self, data):
        self.data=data
        self.reset()

    def reset(self):
        #self.label   = dataObj.NOISE
        self.visited = False
        self.assigned = False

class CachingNeighborFinder():

    __slots__=['cache']

    def __init__(self, dataset, distance):
        self.cache=self._build_cache(dataset, distance)

    def _build_cache(self, dataset, distance):
        ''' build distance cache.
            each vector will compute the distance with others
            distance from others are sorted ASC '''

        distances=dict()
        def _getDistance(a,b):
            a,b=sorted([a,b])
            try:
                d=distances[(a,b)]
            except KeyError:
                d=distance(a,b)
                distances[(a,b)]=d
            return d

        cache=dict()
        for a in dataset:
            pairs = [(_getDistance(a.data, b.data), b) for b in dataset if a != b]
            cache[a] = sorted(pairs, key=lambda p: p[0])

        return cache

    def find_neighbours(self, instance, radius):
        pairs=self.cache[instance]

        """
        find all pairs with radius<=dist
        """
        index=bisect.bisect_right(pairs, (radius,))
        neighbours=[instance for dist,instance in pairs[:index]]
        return neighbours

def dbscan(dataset, radius, minPt, distance, keepNoise=False):
    """
    dataset: as list of data items to be clustered
    radius: the DBSCAN radius parameter
    minPt: the DBSCAN minPt parameter
    distance: a distance function to be used to compare two data items
    keepNoise: if True, each data item that DBSCAN identified as noise will be
    returned in its own cluster
    """
    dataObjSet=[dataObj(d) for d in dataset]
    cnf=CachingNeighborFinder(dataObjSet, distance)
    clusters = []

    if minPt<1:
        minPt=1

    for instance in dataObjSet:
        # skip processed
        if instance.visited == True:
            continue

        instance.visited = True
        neighbours = cnf.find_neighbours(instance, radius)

        if minPt > len(neighbours) + 1:
            #instance.label = dataObj.NOISE
            continue
        else:
            # new cluster
            c = set([instance])
            #c = set(neighbours + [instance])
            clusters.append(c)
            q = deque(neighbours)
            instance.assigned=True

            # expand cluster
            while len(q):
                check_instance = q.pop()

                if not check_instance.visited:
                    check_instance.visited = True
                    neighbours = cnf.find_neighbours(check_instance, radius)

                    if minPt <= len(neighbours) + 1:
                        q.extend(neighbours)

#                    if minPt > len(neighbours) + 1:
#                        # not core, border
#                        check_instance.label = dataObj.BORDER
#                    else:
#                        # core, expand
#                        check_instance.label = dataObj.CORE
#                        for n in neighbours:
#                            if n not in c:
#                                c.add(n)
#                                q.append(n)

                if not check_instance.assigned:
                    c.add(check_instance)
                    check_instance.assigned=True

    """
    by keeping also noisy instances, we make sure that the
    input data equals the (clustered) output data
    """
    if keepNoise:
        noise=[[instance] for instance in dataObjSet if not instance.assigned]
        clusters+=noise

    """
    unpack clustered objects
    """
    clusters=[map(lambda x: x.data, cl) for cl in clusters]

    return clusters
