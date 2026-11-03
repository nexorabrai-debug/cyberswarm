"""Locate optional external OSS tools. Search order: $CYBERSWARM_TOOLBIN, ~/.cyberswarm-tools/bin, PATH."""
import os, shutil
def toolbins():
    return [p for p in (os.environ.get("CYBERSWARM_TOOLBIN"), os.path.expanduser("~/.cyberswarm-tools/bin")) if p]
def which(name):
    if os.environ.get("CYBERSWARM_DISABLE_TOOLS") and name in os.environ["CYBERSWARM_DISABLE_TOOLS"].split(","): return None
    for d in toolbins():
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK): return c
    return shutil.which(name)
