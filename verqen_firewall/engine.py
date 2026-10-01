"""Lazy loader for the VerQen inference engine.

The ``verqen`` package is imported only when a live check is needed, so
policies, adapters and the test suite all work without it installed.
"""

from __future__ import annotations

import os

VERQEN_CHECKPOINT_ENV = "VERQEN_CHECKPOINT"
_INSTALL_HINT = "Install VerQen with: pip install git+https://github.com/ZorQelis-AI/verqen.git"


def load_engine(checkpoint: str | None = None, device: str = "auto", fast: bool = False):
    """Load ``VerqenInferenceEngine`` from *checkpoint* (or the ``VERQEN_CHECKPOINT`` env var).

    Raises ``ValueError`` when no checkpoint is configured and ``ImportError``
    when the ``verqen`` package itself is missing, with an install hint.
    """
    if checkpoint is None:
        checkpoint = os.environ.get(VERQEN_CHECKPOINT_ENV) or None
    if not checkpoint:
        raise ValueError(
            f"No VerQen checkpoint given. Pass checkpoint=... or set {VERQEN_CHECKPOINT_ENV}."
        )
    try:
        from verqen.inference.engine import VerqenInferenceEngine
    except ImportError as exc:
        raise ImportError(
            "The 'verqen' package is required for live checks but is not installed. "
            + _INSTALL_HINT
        ) from exc
    return VerqenInferenceEngine.from_checkpoint(checkpoint, device, fast=fast)
