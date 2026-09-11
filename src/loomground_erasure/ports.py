# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Host stores the erasure reaches through one explicit ports object.

Every port is optional. An absent port is a named blind spot on the report
(``SweepReport.blind_spots`` / ``ExecutionReport.blind_spots``): the sweep
still completes for the chain, and the report says which store was neither
inspected nor erased. Evidence identifiers (pair ids, record refs) are
opaque strings passed through unchanged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import Any, Callable, Optional

REDACTED = "[REDACTED]"

# Port name → what is unknown when the port is absent.
BLIND_SPOT_MEANING: dict[str, str] = {
    "pair_from_event": "pair bodies stored outside the chain event are unseen",
    "discover_descendants": "descendant folders unknown; root swept alone",
    "replace_ci": "host scrub absent; literal case-insensitive scrub used",
    "scan_drafts": "draft files uninspected",
    "redact_drafts": "draft files untouched",
    "scan_cards": "card files uninspected",
    "redact_cards": "card files untouched",
    "erase_versum_mirror": "knowledge mirror of purged pairs neither erased nor certified",
}


@dataclass
class ErasureHost:
    """Callables a host binds; ``None`` means the store is unreachable here.

    - ``pair_from_event(event) -> dict | None`` — resolve a pair body for a chain event.
    - ``discover_descendants(folder, log_root=) -> list[str]`` — folders under ``folder``.
    - ``replace_ci(text, needle) -> (text, count)`` — scrub every occurrence of ``needle``.
    - ``scan_drafts(folder, subject, log_root=) -> {hits: {surface: n}, unreadable: [surface], sealed: bool}``
    - ``redact_drafts(folder, subject, log_root=) -> {ok, redacted: {surface: n}, deleted: [surface]}``
    - ``scan_cards(folder, subject, log_root=) -> {hits: {id: n}, identity: [id], unreadable: [id], sealed: bool}``
    - ``redact_cards(folder, subject, log_root=) -> {ok, redacted: {id: n}, deleted: [id]}``
    - ``erase_versum_mirror(folder, pair_ids, *, physical, reason, actor, log_root) -> (errors, sealed_folders)``
    """

    pair_from_event: Optional[Callable[[Any], Optional[dict]]] = None
    discover_descendants: Optional[Callable[..., list[str]]] = None
    replace_ci: Optional[Callable[[str, str], tuple[str, int]]] = None
    scan_drafts: Optional[Callable[..., dict[str, Any]]] = None
    redact_drafts: Optional[Callable[..., dict[str, Any]]] = None
    scan_cards: Optional[Callable[..., dict[str, Any]]] = None
    redact_cards: Optional[Callable[..., dict[str, Any]]] = None
    erase_versum_mirror: Optional[Callable[..., tuple[list[Exception], list[str]]]] = None

    def absent(self) -> list[str]:
        return [f.name for f in fields(self) if getattr(self, f.name) is None]

    def bound(self) -> list[str]:
        return [f.name for f in fields(self) if getattr(self, f.name) is not None]


def default_pair_from_event(evt: Any) -> Optional[dict]:
    """The chain-native body: ``event.extra["pair"]`` when present."""
    extra = getattr(evt, "extra", None)
    pair = extra.get("pair") if isinstance(extra, dict) else None
    return pair if isinstance(pair, dict) else None


def scrub_literal(text: str, needle: str) -> tuple[str, int]:
    """Fallback for an absent ``replace_ci``: literal, case-insensitive."""
    if not text or not needle:
        return text, 0
    return re.compile(re.escape(needle), re.IGNORECASE).subn(REDACTED, text)


def resolve_pair(host: Optional[ErasureHost], evt: Any) -> Optional[dict]:
    fn = host.pair_from_event if host and host.pair_from_event else default_pair_from_event
    return fn(evt)


def scrub(host: Optional[ErasureHost], text: str, needle: str) -> tuple[str, int]:
    fn = host.replace_ci if host and host.replace_ci else scrub_literal
    return fn(text, needle)


def note_blind_spot(spots: dict[str, list[str]], port: str, folder: str = "*") -> None:
    seen = spots.setdefault(port, [])
    if folder not in seen:
        seen.append(folder)


__all__ = [
    "BLIND_SPOT_MEANING",
    "REDACTED",
    "ErasureHost",
    "default_pair_from_event",
    "note_blind_spot",
    "resolve_pair",
    "scrub",
    "scrub_literal",
]
