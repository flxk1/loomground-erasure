# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""loomground-erasure — controller-signed erasure over a signed audit chain.

Modules: :mod:`.erasure` (request / sweep / execute / status),
:mod:`.pending_erase` (signed markers for sealed folders),
:mod:`.forgotten_subjects` (salted re-ingestion ledger), :mod:`.ports`
(the host stores, injected).

Importing the package points the audit chain's ``purged_pair_ref`` port at
the folder-salted ref so tombstones and trackers name a purged pair the same
way (see ``forgotten_subjects.bind_chain_pair_refs``).
"""
from __future__ import annotations

from . import erasure, forgotten_subjects, pending_erase, ports
from ._version import __version__
from .erasure import (
    STATES,
    ControllerKeyMissingError,
    EraseGuardHit,
    ErasureGuardRegistrationError,
    ExecutionReport,
    SweepHit,
    SweepReport,
    dry_run,
    execute,
    request,
    status,
    sweep,
    verdict_for,
)
from .forgotten_subjects import bind_chain_pair_refs, purged_pair_ref
from .pending_erase import PENDING_ERASE_ENV, PendingEraseError, bind_seal_hooks, feature_enabled
from .ports import BLIND_SPOT_MEANING, ErasureHost

bind_chain_pair_refs()

__all__ = [
    "__version__",
    "erasure", "forgotten_subjects", "pending_erase", "ports",
    "STATES", "ControllerKeyMissingError", "EraseGuardHit",
    "ErasureGuardRegistrationError", "ExecutionReport", "SweepHit", "SweepReport",
    "dry_run", "execute", "request", "status", "sweep", "verdict_for",
    "bind_chain_pair_refs", "purged_pair_ref",
    "PENDING_ERASE_ENV", "PendingEraseError", "bind_seal_hooks", "feature_enabled",
    "BLIND_SPOT_MEANING", "ErasureHost",
]
