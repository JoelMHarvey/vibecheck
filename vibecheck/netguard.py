"""Moved to vibecheck.core.netguard. This name stays so existing imports, scripts and the
GitHub Action keep working; it is the same module object, not a copy."""

import sys

from .core import netguard as _moved

sys.modules[__name__] = _moved
