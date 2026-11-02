"""Goosey package setup configuration.

Defines package metadata, dependencies, console entry points, and package_data
(templates and data files shipped with the distribution).
"""

import re
import sys

from os import path
from setuptools import setup

if sys.version_info < (3,9):
    sys.exit("The current Python version is less than 3.9. Exiting.")
elif sys.version_info >= (3,14):
    sys.exit("The current Python version is greater than 3.13. Exiting.")

def read_version():
    """Single source of truth: parse __version__ from goosey/__init__.py without importing it."""
    init_path = path.join(path.dirname(path.abspath(__file__)), "goosey", "__init__.py")
    with open(init_path, encoding="utf-8") as f:
        match = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)[\'"]', f.read(), re.M)
    if not match:
        sys.exit("Unable to find __version__ in goosey/__init__.py")
    return match.group(1)

requirements_filepath = path.join(path.dirname(path.abspath(__file__)), "requirements.txt")
requirements = open(requirements_filepath).read().split()

setup(name='goosey',
      version=read_version(),
      description='EntraID, Azure, M365, MDE Data Collector',
      author='Claire Casalnova, Jordan Eberst, Nicholas Kantor, Wellington Lee, John Phelps, Victoria Wallace',
      classifiers=[
          'Intended Audience :: Information Technology',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Programming Language :: Python :: 3.13',
      ],
      packages=['goosey'],
      package_data={'goosey': ['templates/*', 'data/*']},
      python_requires='>=3.9',
      install_requires=requirements,
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['goosey=goosey.main:main']
      }
    )
