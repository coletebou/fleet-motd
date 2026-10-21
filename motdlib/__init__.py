"""fleet-motd: a cached, fleet-aware login dashboard.

Two halves share this package:
  * the collector (`motd collect`) runs every source whose cache is due and
    writes one JSON record per source under ~/.cache/motd/v2/src/;
  * the renderer (`motd`, called from zshrc at login) reads only those caches
    plus cheap live probes, so a login never waits on the network.

Stdlib only and Python 3.9 compatible (the Mac's /usr/bin/python3).
"""

VERSION = "2.0.0"
