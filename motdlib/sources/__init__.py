"""Importing this package registers every source with motdlib.registry."""
import importlib
import sys

from . import local  # noqa: F401 — the core host sources are not optional

for _mod in ("fleet", "cloud", "ai", "devops", "checks"):
    try:
        importlib.import_module("%s.%s" % (__name__, _mod))
    except ImportError as e:  # a missing optional module must not break the rest
        if "No module named" not in str(e):
            print("motd: source module %s unavailable: %s" % (_mod, e), file=sys.stderr)
