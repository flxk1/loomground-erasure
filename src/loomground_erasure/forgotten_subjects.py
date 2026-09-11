# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Forgotten-subjects ledger: refuse re-ingestion of an erased subject.

One JSONL row per subject under ``<folder>/forgotten_subjects/``:
``{subject_hash: sha256(salt ␟ subject), salt, added_at, request_id}``. The
salt is folder-scoped; the plaintext subject is never persisted. Matching is
token / full-text, never substring: false negatives (paraphrase) accepted,
false positives refused.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from loomground_audit_chain import mutation_log as _chain

FORGOTTEN_DIR_NAME = "forgotten_subjects"

_SALT_FILE = "salt"
_LEDGER_FILE = "forgotten.jsonl"
_LOCK_FILE = ".ledger.lock"

_TOKEN_RE = re.compile(r"\b\w+\b", re.UNICODE)


class EraseGuardHit(Exception):
    """Raised by an ingest path when :func:`check_text` matches."""

    def __init__(self, hashes: list[str], folder: str):
        self.hashes = list(hashes)
        self.folder = folder
        super().__init__(
            f"erase guard fired in {folder}: {len(hashes)} forgotten "
            f"subject(s) matched. Refusing to re-ingest."
        )


def _folder_dir(folder: str | Path) -> Path:
    return Path(folder).expanduser().resolve() / FORGOTTEN_DIR_NAME


def _salt_path(folder: str | Path) -> Path:
    return _folder_dir(folder) / _SALT_FILE


def _ledger_path(folder: str | Path) -> Path:
    return _folder_dir(folder) / _LEDGER_FILE


@contextmanager
def _ledger_lock(folder: str | Path) -> Iterator[None]:
    lock_path = _folder_dir(folder) / _LOCK_FILE
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        if lock_file.tell() == 0:
            lock_file.write(b"\0")
            lock_file.flush()
            os.fsync(lock_file.fileno())
        try:
            import fcntl
        except ImportError:  # pragma: no cover - Windows
            try:
                import msvcrt
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "no OS file-locking backend for forgotten-subject ledger"
                ) from exc
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _atomic_write_private(path: Path, text: str) -> None:
    """Atomically replace ``path`` with fsynced owner-only UTF-8 text."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _read_or_create_salt(folder: str | Path) -> str:
    sp = _salt_path(folder)
    if sp.exists():
        salt = sp.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", salt):
            raise RuntimeError(f"invalid forgotten-subject salt at {sp}")
        return salt
    salt = secrets.token_hex(32)
    _atomic_write_private(sp, salt + "\n")
    return salt


def _ensure_salt(folder: str | Path) -> str:
    with _ledger_lock(folder):
        return _read_or_create_salt(folder)


def salt_for(folder: str | Path) -> str:
    """The folder's salt, created on first use, never rotated."""
    return _ensure_salt(folder)


def _hash_subject(salt: str, subject: str) -> str:
    normal = subject.strip().lower()
    return hashlib.sha256((salt + "\x1f" + normal).encode("utf-8")).hexdigest()


def opaque_ref(folder: str | Path, text: str, *, domain: str) -> str:
    """``sha256(domain ␟ salt ␟ text)`` — the on-chain stand-in for a
    subject-bearing identifier. ``domain`` separates use sites so refs from
    two domains can never be equality-linked. Text is taken exactly."""
    salt = _ensure_salt(folder)
    return hashlib.sha256(
        (domain + "\x1f" + salt + "\x1f" + text).encode("utf-8")
    ).hexdigest()


def purged_pair_ref(folder: str | Path, pair_id: str) -> str:
    """Purge tombstones, trackers and the composite all name a purged pair by
    this ref, so ``erasure.status`` stitches them by equality."""
    return "pair-ref:" + opaque_ref(folder, pair_id, domain="pair-ref")[:16]


def bind_chain_pair_refs() -> None:
    """Point the audit chain's ``purged_pair_ref`` port at the salted ref, so
    the tombstone the chain writes and the tracker this package writes agree."""
    _chain.purged_pair_ref = purged_pair_ref


def _read_ledger(folder: str | Path) -> list[dict[str, Any]]:
    lp = _ledger_path(folder)
    if not lp.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in lp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return rows


def _read_ledger_strict(folder: str | Path) -> list[dict[str, Any]]:
    lp = _ledger_path(folder)
    if not lp.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lp.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"corrupt forgotten-subject ledger at line {line_number}"
            ) from exc
        if not isinstance(row, dict):
            raise RuntimeError(f"invalid forgotten-subject ledger row at line {line_number}")
        if not row.get("subject_hash") or not row.get("salt"):
            raise RuntimeError(f"incomplete forgotten-subject ledger row at line {line_number}")
        rows.append(row)
    return rows


def _write_rows(folder: str | Path, rows: list[dict[str, Any]]) -> None:
    payload = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    _atomic_write_private(_ledger_path(folder), payload)


def ensure(folder: str | Path, subject: str, request_id: str) -> tuple[str, bool]:
    """Durably guard ``subject``; ``(hash, added)``. Historical rows are
    matched under their own salt."""
    if not subject or not subject.strip():
        raise ValueError("subject must be non-empty")
    with _ledger_lock(folder):
        canonical_salt = _read_or_create_salt(folder)
        rows = _read_ledger_strict(folder)
        for row in rows:
            if _hash_subject(str(row["salt"]), subject) == row["subject_hash"]:
                return str(row["subject_hash"]), False
        h = _hash_subject(canonical_salt, subject)
        rows.append({
            "subject_hash": h,
            "salt": canonical_salt,
            "added_at": time.time(),
            "request_id": str(request_id or ""),
        })
        _write_rows(folder, rows)
        return h, True


def add(folder: str | Path, subject: str, request_id: str) -> str:
    """Append a row (duplicates allowed) and return its salted hash."""
    if not subject or not subject.strip():
        raise ValueError("subject must be non-empty")
    with _ledger_lock(folder):
        salt = _read_or_create_salt(folder)
        rows = _read_ledger_strict(folder)
        subject_hash = _hash_subject(salt, subject)
        rows.append({
            "subject_hash": subject_hash,
            "salt": salt,
            "added_at": time.time(),
            "request_id": str(request_id or ""),
        })
        _write_rows(folder, rows)
        return subject_hash


def contains(folder: str | Path, subject: str) -> bool:
    """Exact salted-hash membership (replay safety), unlike :func:`check`."""
    if not subject or not subject.strip():
        return False
    rows = _read_ledger_strict(folder)
    return any(
        row.get("subject_hash") and row.get("salt")
        and _hash_subject(str(row["salt"]), subject) == row["subject_hash"]
        for row in rows
    )


def list_subjects(folder: str | Path) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in _read_ledger(folder):
        h = row.get("subject_hash", "")
        if not h or h in seen:
            continue
        seen.add(h)
        out.append({
            "subject_hash": h,
            "added_at": row.get("added_at", 0.0),
            "request_id": row.get("request_id", ""),
        })
    return out


def _candidate_strings(text: str) -> list[str]:
    """Every lowercased token plus the whitespace-collapsed full text."""
    if not text:
        return []
    lower = text.strip().lower()
    tokens = set(_TOKEN_RE.findall(lower))
    full_norm = " ".join(lower.split())
    candidates = list(tokens)
    if full_norm:
        candidates.append(full_norm)
    return candidates


def check(folder: str | Path, text: str) -> list[str]:
    """Forgotten-subject hashes whose subject appears in ``text`` as a token
    or as the whole text."""
    if not text:
        return []
    rows = _read_ledger_strict(folder)
    if not rows:
        return []
    candidate_strings = _candidate_strings(text)
    hits: list[str] = []
    seen: set[str] = set()
    for row in rows:
        h_expected = row.get("subject_hash", "")
        salt = row.get("salt", "")
        if not h_expected or not salt or h_expected in seen:
            continue
        for cand in candidate_strings:
            if cand and _hash_subject(salt, cand) == h_expected:
                hits.append(h_expected)
                seen.add(h_expected)
                break
    return hits


def check_text(folder: str | Path, text: str) -> list[str]:
    """Stable ingest-facing alias of :func:`check`."""
    return check(folder, text)


__all__ = [
    "FORGOTTEN_DIR_NAME",
    "EraseGuardHit",
    "add",
    "bind_chain_pair_refs",
    "check",
    "check_text",
    "contains",
    "ensure",
    "list_subjects",
    "opaque_ref",
    "purged_pair_ref",
    "salt_for",
]
