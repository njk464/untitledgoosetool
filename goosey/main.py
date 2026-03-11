#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Main!
Entry point module. Maps CLI subcommands to functions via Google's python-fire library.
Commands: honk, autohonk, conf, d4iot, setup, web, version.
"""

import argparse
import sys
from colored import stylize, attr, fg
import fire

from goosey.honk import honk, autohonk
from goosey.conf import genconf
from goosey.d4iot import d4iot
from goosey.setup_app import setup
from goosey.web import web
import goosey


def version():
	"""
	Display the version
	"""
	print(f"Untitled Goose Tool Version {goosey.__version__}")


def main():
    fire.Fire({"honk": honk,
               "autohonk": autohonk,
               "conf": genconf,
               "d4iot": d4iot,
               "setup": setup,
               "web": web,
               "--version": version})
if __name__ == "__main__":
    main()
