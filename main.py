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

    if args["action"] == "encrypt":
        r = core.PySomCryptware(password=args["password"],
                                keyfile=args["keyfile"],
                                start_path=args["startdir"])
        r.start_crypting()
    elif args["action"] == "decrypt":
        if args["keyfile"]:
            r = core.PySomCryptware(password=args["password"],
                                    keyfile=args["keyfile"],
                                    start_path=args["startdir"])
            r.start_crypting(False)
        else:
            r = core.PySomCryptware(password=args["password"],
                                    keyfile=args["keyfile"],
                                    start_path=args["startdir"])
            r.start_crypting(False)


if __name__ == "__main__":
    import sys

    lets_gerrit()
    sys.exit(0)
