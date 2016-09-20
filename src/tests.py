'''
Created on Jan 21, 2015

@author: gianko

TODO: check what this script does and integrate in guenther.

'''
import itertools


def to_dict(raw):
    return {d[0]: d[1:] for d in raw}


def are_intersect(s1, e1, s2, e2):
    return (s1 <= e2) and (s2 <= e1)


def are_distinguishable(b_i, b_j):
    """
    Check if time intervals are sufficient
    """

    s1, e1 = b_i[1:3]
    s2, e2 = b_j[1:3]

    if not are_intersect(s1, e1, s2, e2):
        # print "Distinguishable by dt"
        # print "---"
        return True

    """
    Ok, time was not sufficient. Check with response code
    """

    codes1 = set()
    codes2 = set()
    if hasattr(b_i[3], '__iter__'):
        codes1 = set(b_i[3])
    else:
        codes1.add(b_i[3])

    if hasattr(b_j[3], '__iter__'):
        codes2 = set(b_j[3])
    else:
        codes2.add(b_j[3])

    if codes1.isdisjoint(codes2):
        # print "Distinguishable by codes"
        # print "---"
        return True

    """
    Ok, neither that. Check with content length
    """
    clen1 = set()
    clen2 = set()
    if hasattr(b_i[4], '__iter__'):
        clen1 = set(b_i[4])
    else:
        clen1.add(b_i[4])

    if hasattr(b_j[4], '__iter__'):
        clen2 = set(b_j[4])
    else:
        clen2.add(b_j[4])

    if clen1.isdisjoint(clen2):
        # print "Distinguishable by clen"
        # print "---"
        return True

    return False


def undistinguishability_matrix(data):
    M = {}
    for b_i, b_j in itertools.product(data.keys(), data.keys()):
        if not are_distinguishable(data[b_i], data[b_j]):
            M.setdefault(b_i, []).append(b_j)
    return M


def facebook():
    """
    Facebook
    """
    raw = [
        ["b1", 0.68679628372192381, 0.67260962749214925,
            0.70098293995169836, 200, 9413, None],
        ["b2", 8.5691676139831543, 8.557518531970473,
            8.5808166959958356, 200, 9413, None],
        ["b3", 0.93790109157562251, 0.8002873765213091,
            1.0755148066299358, 200, 26642, None],
        ["b4", 1.1483073711395264, 0.90865101389303593,
            1.3879637283860169, 200, 16706, None],
        ["b5", 0.81197531223297115, 0.80021507079127285,
            0.82373555367466944, 200, 9413, None],
        ["b6", 0.8139098167419434, 0.80160917145687294,
            0.82621046202701387, 200, 9413, None],
        ["b7", 10.569303107261657, 10.560089504086159,
         10.578516710437155, 200, [15024, 15026], None],
        ["b8", 2.6089818716049193, 1.6628851135567917,
            3.555078629653047, 200, 9413, None]
    ]
    return raw


def livejournal():
    """
    LiveJournal
    """
    raw = [
        ["b1", 0.95158143043518062, 0.63031906569318275,
            1.2728437951771785, 302, 54626, 54623, None],
        ["b2", 20.094485402107239, 19.201253133319728,
         20.987717670894749, 302, 54626, 54623, None],
        ["b3", 0.81897904872894289, 0.66628341231616117,
         0.97167468514172461, 302, 54626, 54623, None],
        ["b4", 0.94571900367736816, 0.4801361399931045,
         1.4113018673616318, 302, 54626, 54623, None],
        ["b5", 1.2030192852020263, 0.95474439227249197,
         1.4512941781315607, 302, 54626, 54623, None],
        ["b6", 20.345381379127502, 19.974959552129668,
         20.715803206125337, 302, 54626, 54623, None],
        ["b7", 20.339768981933595, 19.849604885916317,
         20.829933077950873, 302, 54626, 54623, None],
        ["b8", 4.5072939634323124, 3.8699858896349739,
         5.1446020372296513, 302, 54626, 54623, None]
    ]
    return raw


def googlepick():
    """
    Google OnePick
    """

    raw = [
        ["b1", 0.15382285118103028, 0.11535936430504347,
            0.19228633805701711, 502, 145, None],
        ["b2", 10.059489822387695, 10.01850090954847,
         10.10047873522692, 504, 153, None],
        ["b3", 0.13578214645385742, 0.12759400157848552,
         0.14397029132922931, 200, 5841, None],
        ["b4", 0.14239008426666261, 0.12895360841514814,
         0.15582656011817708, 200, 498, None],
        ["b5", 0.13664779663085938, 0.1291491804951265,
         0.14414641276659226, 404, 1484, None],
        ["b6", 10.051935601234437, 10.049509222525948,
         10.054361979942925, 200, 2347, None],
        ["b7", 10.053472876548767, 10.043003093825392,
         10.063942659272142, 504, 153, None],
        ["b8", 2.8284988164901734, 2.2590320126549543,
         3.3979656203253925, 502, 145, None]
    ]
    return raw


def pinterest():
    """
    Pinterest
    """
    raw = [
        ["b1", 1.2842859029769897, 0.5584246501054323,
            2.0101471558485473, 400, 2458, 2460, None],
        ["b2", 1.0447750806808471, 0.89815974886391414,
         1.1913904124977801, 400, 2458, 2460, None],
        ["b3", 1.3322625637054444, 1.1297513867428546,
         1.5347737406680342, 200, 2418, None],
        ["b4", 1.5545825004577636, 1.1119346211781673,
         1.9972303797373598, 200, 2391, None],
        ["b5", 1.4440611839294433, 1.2514265233183426,
         1.636695844540544, 200, 2400, None],
        ["b6", 1.0437238216400146, 0.85696896255232824,
         1.2304786807277011, 400, 2460, None],
        ["b7", 0.94685156345367427, 0.75197752145561436,
         1.1417256054517342, 400, 2460, None],
        ["b8", 6.9006999015808104, 6.6389953810863735,
         7.1624044220752472, [400, 408], 2451, 2435, None]
    ]
    return raw


def ourwebapp():
    """
    OurWebApp
    """

    raw = [
        ["b1", 0.0019653320312500002, 0.0018158703174851207,
            0.0021147937450148799, 500, 1529, None],
        ["b2", 0.0021627187728881837, 0.0018295335768267877,
         0.0024959039689495797, 500, 1529, None],
        ["b3", 0.0019697904586791991, 0.0016379928900223078,
         0.0023015880273360902, 500, 1529, None],
        ["b4", 0.0027208566665649415, 0.0015886503627080507,
         0.0038530629704218323, 500, 1529, None],
        ["b5", 0.0020625114440917967, 0.001801987639760656,
         0.0023230352484229374, 500, 1529, None],
        ["b6", 0.0018558025360107422, 0.0018175336234125927,
         0.0018940714486088918, 500, 1529, None],
        ["b7", 0.001874852180480957, 0.0017513489038905926,
         0.0019983554570713216, 500, 1529, None],
        ["b8", 0.0019555091857910156, 0.0017655920387439207,
         0.0021454263328381106, 500, 1529, None]
    ]
    return raw


def twitter():
    raw = [
        ["b1", 0.6115087032318115, 0.59052542166781807,
            0.63249198479580493, 200, 321, None],
        ["b2", 0.62132291793823247, 0.59499391825445713,
         0.6476519176220078, 200, 321, None],
        ["b3", 0.59547197818756104, 0.58433589045984879,
         0.60660806591527328, 200, 328, None],
        ["b4", 0.63053698539733882, 0.60898029008205468,
         0.65209368071262297, 200, 325, None],
        ["b5", 0.60042693614959719, 0.59101956949168144,
         0.60983430280751294, 200, 326, None],
        ["b6", 0.60903787612915039, 0.57777961179469528,
         0.6402961404636055, 200, 321, None],
        ["b7", 0.60878505706787112, 0.58918698113922019,
         0.62838313299652204, 200, 321, None],
        ["b8", 0.49912247657775877, 0.47343415649316373,
         0.52481079666235386, 403, 30, None]
    ]

    return raw


def capturefullpage():

    raw = [
        ["b1", 0.06231038570404053, 0.061316859410940144,
            0.063303911997140916, 200, 2103, None],
        ["b2", 0.062569689750671384, 0.061904486116429604,
         0.063234893384913171, 200, 2103, None],
        ["b3", 0.062788319587707517, 0.061405939628864648,
         0.064170699546550386, 200, 2111, None],
        ["b4", 0.065358996391296387, 0.058393610861671247,
         0.072324381920921527, 200, 2108, None],
        ["b5", 0.062899732589721674, 0.061393174037543879,
         0.064406291141899469, 200, 2109, None],
        ["b6", 0.064411711692810056, 0.0591379290985901,
         0.069685494287030011, 200, 2103, None],
        ["b7", 0.062500476837158203, 0.061664086229105124,
         0.063336867445211276, 200, 2103, None],
        ["b8", 0.062239766120910645, 0.062103787883014745,
         0.062375744358806544, 200, 2088, None]
    ]
    return raw


def fake():
    """
    Fake 1
    """

    raw = [
        ["b1", 0.0019653320312500002, 0.0018158703174851207,
            0.0021147937450148799, 500, 3453, None],
        ["b2", 0.0021627187728881837, 0.0018295335768267877,
         0.0024959039689495797, 200, 1529, None],
        ["b3", 0.0019697904586791991, 0.0016379928900223078,
         0.0023015880273360902, 200, 1529, None],
        ["b4", 0.0027208566665649415, 0.0015886503627080507,
         0.0038530629704218323, [200, 400], 1529, None],
        ["b5", 0.2020625114440917967, 0.201801987639760656,
         0.0023230352484229374, 500, 1529, None],
        ["b6", 0.0018558025360107422, 0.0018175336234125927,
         0.0018940714486088918, 500, 1529, None],
        ["b7", 0.001874852180480957, 0.0017513489038905926,
         0.0019983554570713216, 500, 1801, None],
        ["b8", 0.0019555091857910156, 0.0017655920387439207,
         0.0021454263328381106, 500, [1529, 1800], None]
    ]
    return raw


if __name__ == '__main__':

    raw = facebook()
    raw = livejournal()
    raw = googlepick()
    raw = pinterest()
    #raw = ourwebapp()
    #raw = twitter()
    #raw = fake()
    raw = capturefullpage()

    data = to_dict(raw)

    #online, offline= host_discovery(data)
    # print "HOST DISCOVERY ====================="
    # print "Online   :", ", ".join(sorted(online))
    # print "Offline  :", ", ".join(sorted(offline))

    #exist, not_exist_404, not_exist = app_fingerprinting(data)
    # print "APP FINGERPRINTING ================="
    # print "Exists        :", ", ".join(sorted(exist))
    # print "Not exists 404:", ", ".join(sorted(not_exist_404))
    # print "Not exists    :", ", ".join(sorted(not_exist))

    #closed, filtered, open = port_scanning(data)
    # print "PORT SCANNING ======================"
    # print "Closed   :", ", ".join(sorted(closed))
    # print "Filtered :", ", ".join(sorted(filtered))
    # print "Open     :", ", ".join(sorted(open))

    M = undistinguishability_matrix(data)
    print "UNDISTINGUISHABILITY MATRIX ========"
    for k in sorted(M.keys()):
        print k, "=", ",".join(M[k])

    """
    PORT SCANNING STATUS
    """
    SCA_STATUS_P_CLOSED = 1
    SCA_STATUS_P_FILTERED = 2
    SCA_STATUS_P_OPEN = 3

    """
    HOST DISCOVERY
    """
    SCA_STATUS_H_ONLINE = 10
    SCA_STATUS_H_OFFLINE = 20

    """
    APP FINGERPRINT
    """
    SCA_STATUS_R_EXIST = 100
    SCA_STATUS_R_NON_EXIST_404 = 200
    SCA_STATUS_R_NON_EXIST = 300

    labels = {
        1: "P_CLOSED",
        2: "P_FILTERED",
        3: "P_OPEN",

        10: "H_ONLINE",
        20: "H_OFFLINE",

        100: "R_EXIST",
        200: "R_NEXISTS_404",
        300: "R_NEXISTS"
    }

    b_map = {
        "b1": [SCA_STATUS_P_CLOSED, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
        "b2": [SCA_STATUS_P_FILTERED, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
        "b3": [SCA_STATUS_P_OPEN, SCA_STATUS_R_EXIST, SCA_STATUS_H_ONLINE],
        "b4": [SCA_STATUS_P_OPEN, SCA_STATUS_R_EXIST, SCA_STATUS_H_ONLINE],
        "b5": [SCA_STATUS_P_OPEN, SCA_STATUS_R_NON_EXIST_404, SCA_STATUS_H_ONLINE],
        "b6": [SCA_STATUS_P_OPEN, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
        "b7": [SCA_STATUS_P_OPEN, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
        "b8": [SCA_STATUS_H_OFFLINE]
    }

    dist_behav = {}
    for k in M.keys():
        for k_i in M[k]:
            for b in b_map[k_i]:
                dist_behav.setdefault(k, (set(), set(), set()))
                el = dist_behav[k]
                if b in [SCA_STATUS_P_OPEN, SCA_STATUS_P_CLOSED, SCA_STATUS_P_FILTERED]:
                    el[2].add(labels[b])
                if b in [SCA_STATUS_R_EXIST, SCA_STATUS_R_NON_EXIST_404, SCA_STATUS_R_NON_EXIST]:
                    el[1].add(labels[b])
                if b in [SCA_STATUS_H_ONLINE, SCA_STATUS_H_OFFLINE]:
                    el[0].add(labels[b])

    print "STATES FOR BEHAVIORS ========"
    max_col = [7, 7, 7]
    for k in sorted(dist_behav):
        max_col[0] = max(
            max_col[0], len(", ".join(list(dist_behav[k][0])))) + 1
        max_col[1] = max(
            max_col[1], len(", ".join(list(dist_behav[k][1])))) + 1
        max_col[2] = max(
            max_col[2], len(", ".join(list(dist_behav[k][2])))) + 1

    print "{0} {1} {2} {3}".format("Behav.", "Host Disc.".ljust(max_col[0]), "WebApp Disc.".ljust(max_col[1]), "Port Scan".ljust(max_col[2]))
    for k in sorted(dist_behav):
        print "{0} {1} {2} {3}".format(k.ljust(6), ", ".join(list(dist_behav[k][0])).ljust(max_col[0]), ", ".join(list(dist_behav[k][1])).ljust(max_col[1]), ", ".join(list(dist_behav[k][2])).ljust(max_col[2]))

    print "CLASSES OF STATES ============"
    S_classes = {}

    els = [[k] + sorted([list(v[0]) + list(v[1]) + list(v[2])])
           for k, v in dist_behav.items()]
    els = sorted(els, key=lambda el: el[1])
    for ls, b in itertools.groupby(els, lambda el: el[1]):
        S_classes[frozenset([p[0] for p in list(b)])] = ls

    for k, v in sorted(S_classes.items(), key=lambda el: sorted(list(el[0]))):
        print "-".join(sorted(list(k))), "\t", ", ".join(v)
