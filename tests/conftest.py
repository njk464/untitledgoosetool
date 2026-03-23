"""pytest configuration: ensure the worktree's goosey package takes precedence.

When multiple editable installs of goosey exist (the main tree and the worktree),
Python's import machinery may resolve to whichever was installed last. Prepending
the worktree root to sys.path guarantees tests always exercise the code under
development in this worktree rather than a stale installed version.
"""

import os
import sys

# Worktree root is one level above this conftest.py (tests/ → worktree root)
_WORKTREE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if _WORKTREE_ROOT not in sys.path:
    sys.path.insert(0, _WORKTREE_ROOT)
