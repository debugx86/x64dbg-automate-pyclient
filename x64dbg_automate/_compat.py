"""Compatibility shims for the oldest Python this package claims to support.

``pyproject.toml`` declares ``requires-python = ">=3.10"``, but the package is
built on ``enum.StrEnum``, which only exists from 3.11 onwards. Importing on
3.10 therefore raised ``ImportError: cannot import name 'StrEnum'`` before a
single line of package code ran — the package installed fine and was simply
unusable (caught by the CI matrix, py3.10 leg).
"""

import sys
from enum import Enum

if sys.version_info >= (3, 11):  # pragma: no cover - the normal path
    from enum import StrEnum
else:  # pragma: no cover - exercised by the py3.10 CI leg only
    class StrEnum(str, Enum):
        """Backport of :class:`enum.StrEnum`.

        Matches CPython semantics for the parts this package relies on: members
        compare equal to their string value and ``str()`` yields the value (not
        ``"Class.MEMBER"``). ``auto()`` is not used anywhere in the package, so
        the auto-lowercasing helper is not reproduced.
        """

        def __str__(self) -> str:
            return str(self.value)


__all__ = ["StrEnum"]
