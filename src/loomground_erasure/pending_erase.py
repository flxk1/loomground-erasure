# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Pending-erasure markers: erasure against a SEALED folder without
decrypting it. A signed marker is written beside the ``<hash>.sealed`` blob
at erasure time; ``unseal_folder`` verifies every marker fail-closed BEFORE
restoring plaintext and applies the purge only afterwards.

Feature flag ``WORKSPACE_PENDING_ERASE=1`` (default off).

Marker security: the body is controller-signed first (when a controller key
exists) and operator-signed last over ``body + controller_sig``; the body
binds ``folder_hash`` and ``sealed_blob_fingerprint`` so a moved or replayed
marker is rejected. Subject matching at apply time is a contiguous n-gram of
``subject_token_count`` tokens, never substring.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from loomground_audit_chain import signing
from loomground_audit_chain.mutation_log import _file_lock
from loomground_lock import host_deps as _lock_host_deps
from loomground_lock import seal
from loomground_workspace.workspace_registry import list_known_workspaces

from . import forgotten_subjects
from .ports import ErasureHost, resolve_pair

PENDING_ERASE_ENV = "WORKSPACE_PENDING_ERASE"

_MARKER_SUFFIX = ".pending-erase.jsonl"


class PendingEraseError(RuntimeError):
    """A marker could not be armed, verified, or applied."""


def feature_enabled() -> bool:
    return os.environ.get(PENDING_ERASE_ENV) == "1"


def _canonical_bytes(d: dict[str, Any]) -> bytes:
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


_BODY_FIELDS = (
    "folder_hash", "sealed_blob_fingerprint", "salt", "subject_hash",
    "subject_token_count", "request_id", "legal_basis", "requester_ref",
    "reason_safe", "created_at", "marker_id", "controller_keyid",
    "operator_keyid",
)


def _body_of(marker: dict[str, Any]) -> dict[str, Any]:
    return {k: marker.get(k) for k in _BODY_FIELDS}


def _resolve_sealed_paths(folder: str | Path, log_root: str | Path | None) -> tuple[Path, Path]:
    log_dir = seal._resolve_log_dir(folder, log_root)
    return log_dir, seal._sealed_path(log_dir)


def _marker_ledger_path(folder: str | Path, log_root: str | Path | None) -> Path:
    log_dir, _sealed = _resolve_sealed_paths(folder, log_root)
    return log_dir.parent / (log_dir.name + _MARKER_SUFFIX)


def _read_markers(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _write_markers(path: Path, markers: list[dict[str, Any]]) -> None:
    payload = "".join(json.dumps(m, ensure_ascii=False) + "\n" for m in markers)
    forgotten_subjects._atomic_write_private(path, payload)


def _locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ("." + path.name + ".lock")
    fh = open(lock_path, "a+", encoding="utf-8")
    return fh, _file_lock(fh, exclusive=True)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_subject_tokens(subject_norm: str) -> tuple[str, int]:
    """The one place a marker's ``subject_hash`` input and ``subject_token_count``
    come from; the same tokeniser the apply-time matcher uses."""
    tokens = forgotten_subjects._TOKEN_RE.findall(subject_norm.strip().lower())
    return " ".join(tokens), max(1, len(tokens))


def arm_marker(
    folder: str | Path,
    *,
    subject_norm: str,
    request_id: str,
    legal_basis: str,
    requester_ref: str,
    reason_safe: str,
    log_root: str | Path | None = None,
) -> dict[str, Any]:
    """Arm one signed marker for a SEALED folder; registers the subject in
    that folder's own ledger. Deduplicates on
    ``(folder_hash, subject_hash, sealed_blob_fingerprint)``."""
    log_dir, sealed_path = _resolve_sealed_paths(folder, log_root)
    if not sealed_path.exists():
        raise PendingEraseError(f"cannot arm a pending-erase marker: {folder} is not sealed")

    forgotten_subjects.ensure(folder, subject_norm, request_id=request_id)
    salt = forgotten_subjects.salt_for(folder)
    blob_fingerprint = _sha256_hex(sealed_path.read_bytes())
    canonical_subject, subject_token_count = _canonical_subject_tokens(subject_norm)
    subject_hash = forgotten_subjects._hash_subject(salt, canonical_subject)

    has_controller = signing.public_controller_key_fingerprint() is not None

    ledger_path = _marker_ledger_path(folder, log_root)
    fh, lock_cm = _locked(ledger_path)
    try:
        with lock_cm:
            markers = _read_markers(ledger_path)
            for existing in markers:
                if (existing.get("folder_hash") == log_dir.name
                        and existing.get("subject_hash") == subject_hash
                        and existing.get("sealed_blob_fingerprint") == blob_fingerprint):
                    return existing

            body: dict[str, Any] = {
                "folder_hash": log_dir.name,
                "sealed_blob_fingerprint": blob_fingerprint,
                "salt": salt,
                "subject_hash": subject_hash,
                "subject_token_count": subject_token_count,
                "request_id": request_id,
                "legal_basis": legal_basis,
                "requester_ref": requester_ref,
                "reason_safe": reason_safe,
                "created_at": time.time(),
                "marker_id": "pending-erase:" + uuid.uuid4().hex[:16],
                "controller_keyid": (signing.public_controller_key_fingerprint()
                                     if has_controller else None),
                "operator_keyid": signing.public_key_fingerprint(),
            }
            if has_controller:
                try:
                    controller_sig = signing.sign_with_controller(_canonical_bytes(body))
                except Exception:
                    controller_sig = ""
            else:
                controller_sig = ""
            op_payload = dict(body)
            op_payload["controller_sig"] = controller_sig
            operator_sig = signing.sign_bytes(_canonical_bytes(op_payload))

            marker: dict[str, Any] = dict(body)
            marker["controller_sig"] = controller_sig
            marker["operator_sig"] = operator_sig
            markers.append(marker)
            _write_markers(ledger_path, markers)
    finally:
        fh.close()
    return marker


def discover_sealed_in_scope(
    folder_context: str,
    *,
    cascade: bool,
    log_root: str | Path | None = None,
) -> list[str]:
    """The root if sealed, plus (when cascading) every REGISTERED workspace
    under it that is sealed. An unregistered sealed descendant is unreached."""
    ctx = str(Path(folder_context).expanduser().resolve())
    out: set[str] = set()
    if seal.is_sealed(ctx, log_root=log_root):
        out.add(ctx)
    if cascade:
        ctx_prefix = ctx if ctx.endswith("/") else ctx + "/"
        try:
            rows = list_known_workspaces(Path(log_root) if log_root else None)
        except Exception:
            rows = []
        for row in rows:
            fp = str(row.get("path") or "")
            if fp and (fp == ctx or fp.startswith(ctx_prefix)):
                try:
                    if seal.is_sealed(fp, log_root=log_root):
                        out.add(fp)
                except Exception:
                    continue
    return sorted(out)


def verify_markers_for_unseal(
    folder: str | Path,
    *,
    log_dir: Path,
    sealed_path: Path,
    log_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Verify every marker for ``folder``; raise ``seal.SealError`` on the
    first invalid one (nothing restored, nothing deleted). ``[]`` when none."""
    ledger_path = log_dir.parent / (log_dir.name + _MARKER_SUFFIX)
    markers = _read_markers(ledger_path)
    if not markers:
        return []
    current_blob_fingerprint = _sha256_hex(sealed_path.read_bytes())
    for marker in markers:
        body = _body_of(marker)
        controller_sig = str(marker.get("controller_sig") or "")
        operator_sig = str(marker.get("operator_sig") or "")
        pub = signing.identity_public_key_or_none()
        if pub is None:
            raise seal.SealError(
                "pending-erase marker verification failed: no operator "
                "identity key registered — refusing to unseal")
        op_payload = dict(body)
        op_payload["controller_sig"] = controller_sig
        if not signing.verify_signature(_canonical_bytes(op_payload), operator_sig, pub):
            raise seal.SealError(
                "pending-erase marker verification failed: operator "
                "signature invalid — refusing to unseal (nothing restored)")
        if body.get("controller_keyid") is not None:
            if not controller_sig or not signing.verify_controller_signature_strict(
                _canonical_bytes(body), controller_sig
            ):
                raise seal.SealError(
                    "pending-erase marker verification failed: claimed "
                    "controller co-signature is missing or invalid — "
                    "refusing to unseal (nothing restored)")
        if body.get("folder_hash") != log_dir.name:
            raise seal.SealError(
                "pending-erase marker verification failed: folder_hash "
                "does not match the folder being unsealed — refusing to "
                "unseal (nothing restored)")
        if body.get("sealed_blob_fingerprint") != current_blob_fingerprint:
            raise seal.SealError(
                "pending-erase marker verification failed: sealed blob "
                "fingerprint mismatch — refusing to unseal (nothing restored)")
    return markers


def _select_matching_pairs(
    folder: str,
    salt: str,
    subject_hash: str,
    subject_token_count: int,
    *,
    log_root: str | Path | None,
    host: Optional[ErasureHost] = None,
) -> tuple[set[str], set[str]]:
    """``(pair_ids, matched_windows)``: every pair whose haystack holds a
    contiguous ``subject_token_count``-token window hashing to ``subject_hash``."""
    from .erasure import _event_text_haystack
    from loomground_audit_chain.mutation_log import MutationLog

    log = MutationLog(folder, log_root=log_root)
    n = max(1, int(subject_token_count) or 1)
    pair_ids: set[str] = set()
    matched: set[str] = set()
    for evt in log.replay():
        pair = resolve_pair(host, evt)
        haystack = _event_text_haystack(evt, pair)
        if not haystack:
            continue
        tokens = forgotten_subjects._TOKEN_RE.findall(haystack.strip().lower())
        if len(tokens) < n:
            continue
        for i in range(len(tokens) - n + 1):
            window = " ".join(tokens[i:i + n])
            if forgotten_subjects._hash_subject(salt, window) == subject_hash:
                pair_ids.add(evt.pair_id)
                matched.add(window)
    return pair_ids, matched


def apply_markers(
    folder: str | Path,
    markers: list[dict[str, Any]],
    *,
    log_root: str | Path | None = None,
    actor: str = "system:pending-erase",
    host: Optional[ErasureHost] = None,
) -> dict[str, Any]:
    """Apply VERIFIED markers to a now-plaintext folder. Idempotent; a marker
    leaves the ledger only after its own apply succeeded. Absent host ports
    are named under ``blind_spots``."""
    from loomground_audit_chain.mutation_log import LogEvent, MutationLog
    from loomground_audit_chain.audit_drop import record as _record_drop

    folder_str = str(folder)
    ledger_path = _marker_ledger_path(folder, log_root)
    applied_marker_ids: list[str] = []
    total_purged_pairs = 0
    total_purged_events = 0
    errors: list[dict[str, Any]] = []
    blind_spots: dict[str, list[str]] = {}
    applied_ids_this_call: set[str] = set()

    for marker in markers:
        marker_id = str(marker.get("marker_id", ""))
        try:
            pair_ids, candidates = _select_matching_pairs(
                folder_str, str(marker.get("salt", "")),
                str(marker.get("subject_hash", "")),
                int(marker.get("subject_token_count", 1) or 1),
                log_root=log_root, host=host)
            log = MutationLog(folder_str, log_root=log_root)
            purged_this_marker: set[str] = set()
            purged_events_this_marker = 0
            reason = f"[erase-req:{marker.get('request_id', '')}] {marker.get('reason_safe', '')}"
            for pid in sorted(pair_ids):
                n = log.purge(
                    pid,
                    legal_basis=str(marker.get("legal_basis", "")),
                    requester_ref=str(marker.get("requester_ref", "")),
                    reason=reason,
                )
                if n:
                    purged_this_marker.add(pid)
                    purged_events_this_marker += int(n)

            if purged_this_marker:
                if host and host.erase_versum_mirror:
                    versum_errors, _sealed_here = host.erase_versum_mirror(
                        folder_str, purged_this_marker, physical=True,
                        reason=reason, actor=actor, log_root=log_root)
                    for verr in versum_errors:
                        errors.append({"marker_id": marker_id,
                                       "versum_purge": f"{type(verr).__name__}: {verr}"})
                else:
                    blind_spots.setdefault("erase_versum_mirror", []).append(folder_str)

            for cand in candidates:
                if not cand:
                    continue
                for port in ("redact_drafts", "redact_cards"):
                    fn = getattr(host, port, None) if host else None
                    if fn is None:
                        if folder_str not in blind_spots.setdefault(port, []):
                            blind_spots[port].append(folder_str)
                        continue
                    try:
                        fn(folder_str, cand, log_root=log_root)
                    except Exception as e:  # pragma: no cover - best-effort parity
                        errors.append({"marker_id": marker_id, port: f"{type(e).__name__}: {e}"})

            log.append(LogEvent(
                event="system",
                folder_path=folder_str,
                pair_id=f"pending-erase-applied:{marker_id}",
                channel="system",
                actor=actor,
                extra={
                    "kind": "erasure_pending_applied",
                    "request_id": str(marker.get("request_id", "")),
                    "marker_id": marker_id,
                    "legal_basis": str(marker.get("legal_basis", "")),
                    "requester_ref": str(marker.get("requester_ref", "")),
                    "reason": str(marker.get("reason_safe", "")),
                    "subject_preview": "[REDACTED]",
                    "affected_pair_count": len(purged_this_marker),
                    "purged_event_count": purged_events_this_marker,
                },
            ))
            total_purged_pairs += len(purged_this_marker)
            total_purged_events += purged_events_this_marker
            applied_marker_ids.append(marker_id)
            applied_ids_this_call.add(marker_id)
        except Exception as e:  # noqa: BLE001 - one bad marker must not sink the rest
            errors.append({"marker_id": marker_id, "error": f"{type(e).__name__}: {e}"})
            _record_drop("pending_erase.apply_markers", e,
                         request_id=str(marker.get("request_id", "")), log_root=log_root)

    if applied_ids_this_call:
        fh, lock_cm = _locked(ledger_path)
        try:
            with lock_cm:
                current = _read_markers(ledger_path)
                survivors = [m for m in current
                             if str(m.get("marker_id", "")) not in applied_ids_this_call]
                _write_markers(ledger_path, survivors)
        finally:
            fh.close()

    return {
        "applied_marker_ids": applied_marker_ids,
        "purged_pair_count": total_purged_pairs,
        "purged_event_count": total_purged_events,
        "errors": errors,
        "blind_spots": blind_spots,
    }


def bind_seal_hooks(host: Optional[ErasureHost] = None) -> None:
    """Register verify/apply on ``loomground_lock.host_deps`` so
    ``unseal_folder`` runs them; both are no-ops while the feature is off."""
    def _verify(folder, *, log_dir, sealed_path, log_root=None):
        if not feature_enabled():
            return []
        return verify_markers_for_unseal(
            folder, log_dir=log_dir, sealed_path=sealed_path, log_root=log_root)

    def _apply(folder, markers, *, log_root=None):
        return apply_markers(folder, markers, log_root=log_root, host=host)

    _lock_host_deps.register(pending_erase_verify=_verify, pending_erase_apply=_apply)


__all__ = [
    "PENDING_ERASE_ENV",
    "PendingEraseError",
    "apply_markers",
    "arm_marker",
    "bind_seal_hooks",
    "discover_sealed_in_scope",
    "feature_enabled",
    "verify_markers_for_unseal",
]
