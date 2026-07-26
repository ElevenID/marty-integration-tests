"""Value-free stage boundaries for official EUDI interoperability fixtures."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager

_STAGE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class EUDIInteropStageError(RuntimeError):
    """A public-safe fixture boundary failure without nested protocol values."""


@contextmanager
def eudi_stage(stage: str) -> Iterator[None]:
    """Replace arbitrary nested failures with one code-owned stage identifier."""

    if not _STAGE.fullmatch(stage):
        raise ValueError("EUDI interoperability stage must be a bounded slug")
    try:
        yield
    except EUDIInteropStageError:
        raise
    except Exception as exc:
        # Do not chain the source exception into JUnit. The production
        # services retain their own private logs, while published evidence
        # receives only this stable boundary.
        status_code = getattr(exc, "status_code", None)
        suffix = f"-http-{status_code}" if isinstance(status_code, int) and 400 <= status_code <= 599 else ""
        raise EUDIInteropStageError(f"eudi-stage-{stage}{suffix}") from None
