"""Goosey package setup configuration.

Defines package metadata, dependencies, console entry points, and package_data
(templates and data files shipped with the distribution).
"""

import re
import sys
import sysconfig

from os import path
from setuptools import setup

# @decision DEC-PY-001
# @title Require a FREE-THREADED CPython >= 3.14 (3.14t); fail the install on anything else
# @status accepted
# @rationale goosey depends on upstream Hql main, whose pyproject requires Python >= 3.14
#   and pulls polars_runtime_32 as direct-URL wheels published ONLY for the cp314t
#   (free-threaded) ABI on linux x86_64/aarch64, macOS arm64 and Windows amd64.
#   Verified 2026-11-02 with a GIL CPython 3.14.10, installing pyhql from the
#   pinned commit aborts with "wheel is compatible with free-threaded CPython 3.14 (cp314t), but
#   you're using CPython 3.14 (cp314)".  So a GIL build cannot work, and failing here
#   gives a clear message instead of an obscure resolver error.  Py_GIL_DISABLED is the
#   build-time flag (sys._is_gil_enabled() can be flipped at run time by PYTHON_GIL=1).
MIN_PYTHON = (3, 14)

if sys.version_info < MIN_PYTHON:
    sys.exit("goosey requires Python 3.14 or newer (free-threaded build, 'python3.14t'); "
             "found %d.%d. See README.md for install steps." % sys.version_info[:2])
if not sysconfig.get_config_var("Py_GIL_DISABLED"):
    sys.exit("goosey requires a FREE-THREADED Python 3.14 build ('python3.14t'): its HQL engine "
             "(Hashfastr/Hql) ships polars only for the cp314t ABI. This interpreter has the GIL "
             "enabled. Install one with e.g. 'uv python install 3.14t' and re-create the virtualenv. "
             "See README.md.")

def read_version():
    """Single source of truth: parse __version__ from goosey/__init__.py without importing it."""
    init_path = path.join(path.dirname(path.abspath(__file__)), "goosey", "__init__.py")
    with open(init_path, encoding="utf-8") as f:
        match = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)[\'"]', f.read(), re.M)
    if not match:
        sys.exit("Unable to find __version__ in goosey/__init__.py")
    return match.group(1)

requirements_filepath = path.join(path.dirname(path.abspath(__file__)), "requirements.txt")


def read_requirements(filepath):
    """Parse requirements.txt into PEP 508 strings (one per line, comments/blank skipped).

    A line may contain spaces (e.g. pkg @ git+https://...), so splitting on
    whitespace would corrupt it.
    """
    reqs = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = re.sub(r"(^|\s)#.*$", "", line).strip()
            if line:
                reqs.append(line)
    return reqs


requirements = read_requirements(requirements_filepath)

setup(name='goosey',
      version=read_version(),
      description='EntraID, Azure, M365, MDE Data Collector',
      author='Claire Casalnova, Jordan Eberst, Nicholas Kantor, Wellington Lee, John Phelps, Victoria Wallace',
      classifiers=[
          'Intended Audience :: Information Technology',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.14',
          'Programming Language :: Python :: Implementation :: CPython',
      ],
      packages=['goosey'],
      package_data={'goosey': ['templates/*', 'data/*']},
      python_requires='>=3.14',
      install_requires=requirements,
      zip_safe=False,
      entry_points={
          'console_scripts': ['goosey=goosey.main:main']
      }
    )
