# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Erasure protocol over a signed audit chain.

Three states: ``request`` writes an ``ERASURE_REQUESTED`` event and acts on
nothing; ``sweep`` / ``dry_run`` previews; ``execute`` purges every matching
pair, writes one composite tombstone and registers the subject in the
forgotten-subjects ledger. Host stores are reached through
:class:`~loomground_erasure.ports.ErasureHost`; an absent port is a named
blind spot on the report, never a silent skip.

Failure modes: missing ``legal_basis`` / ``requester_ref`` / ``reason`` or an
empty subject → ``ValueError``; a guard that cannot be registered →
``ErasureGuardRegistrationError`` before any destructive step.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from loomground_audit_chain import signing
from loomground_audit_chain.audit_drop import record as _record_drop
from loomground_audit_chain.mutation_log import (
    LOG_ROOT_DEFAULT,
    VALID_LEGAL_BASES,
    LogEvent,
    MutationLog,
)
from loomground_governance import vocabulary
from loomground_lock import seal

from . import forgotten_subjects, pending_erase
from .ports import REDACTED, ErasureHost, note_blind_spot, resolve_pair, scrub, scrub_literal

STATES = ("request", "sweep", "dry_run", "status", "execute")


def _alphabet_member(name: str) -> str:
    voc = vocabulary("verdicts")
    if name not in voc["alphabet"]:
        raise LookupError(f"{name!r} is not in the verdict alphabet")
    return name


def _releasing() -> str:
    voc = vocabulary("verdicts")
    members = [k for k, v in voc["releases_at_master"].items() if v is True]
    if len(members) != 1 or members[0] not in voc["alphabet"]:
        raise LookupError("verdict vocabulary has no single releasing member")
    return members[0]


def verdict_for(state: str, *, controller_present: Optional[bool] = None,
                require_controller: bool = False) -> str:
    """The verdict a state carries, in the alphabet read from
    ``loomground_governance.vocabulary("verdicts")``: ``request`` is held for
    a person; ``sweep`` / ``dry_run`` / ``status`` read only and release;
    ``execute`` purges and so releases, whether the controller key co-signed
    (``erasure_mode`` two-key) or the operator key signed alone (single-key).
    ``refused`` names the one execute that purges nothing —
    ``require_controller=True`` with no controller key. An unknown state is
    held."""
    state = (state or "").strip().lower()
    if state == "request":
        return _alphabet_member("human")
    if state in ("sweep", "dry_run", "status"):
        return _releasing()
    if state == "execute":
        present = (signing.public_controller_key_fingerprint() is not None
                   if controller_present is None else controller_present)
        if require_controller and not present:
            return _alphabet_member("refused")
        return _releasing()
    return _alphabet_member("human")


class ControllerKeyMissingError(RuntimeError):
    """``execute(require_controller=True)`` with no controller key registered.
    Nothing was purged; ``verdict`` is the word for that."""

    @property
    def verdict(self) -> str:
        return verdict_for("execute", controller_present=False,
                           require_controller=True)


@dataclass
class SweepHit:
    """One match for the subject inside one folder's log."""

    folder: str
    pair_id: str
    kind: str  # pair | capture_llm | capture_web | derived | draft | card
    audit_id: str = ""
    snippet: str = ""


@dataclass
class SweepReport:
    """What the sweep would touch. ``*_sealed`` name folders whose store is
    inside a seal blob; ``blind_spots`` maps an absent port to the folders it
    left uninspected (``"*"`` = every folder)."""

    subject: str
    folder_context: str
    cascade: bool
    hits_by_kind: dict[str, list[SweepHit]] = field(default_factory=dict)
    hits_by_folder: dict[str, int] = field(default_factory=dict)
    estimated_tombstone: dict[str, Any] = field(default_factory=dict)
    drafts_sealed: list[str] = field(default_factory=list)
    cards_sealed: list[str] = field(default_factory=list)
    versum_sealed: list[str] = field(default_factory=list)
    pending_erase_queued: list[str] = field(default_factory=list)
    blind_spots: dict[str, list[str]] = field(default_factory=dict)

    def total_hits(self) -> int:
        return sum(len(v) for v in self.hits_by_kind.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "folder_context": self.folder_context,
            "cascade": self.cascade,
            "hits_by_kind": {k: [asdict(h) for h in v] for k, v in self.hits_by_kind.items()},
            "hits_by_folder": dict(self.hits_by_folder),
            "estimated_tombstone": dict(self.estimated_tombstone),
            "drafts_sealed": list(self.drafts_sealed),
            "cards_sealed": list(self.cards_sealed),
            "versum_sealed": list(self.versum_sealed),
            "pending_erase_queued": list(self.pending_erase_queued),
            "blind_spots": {k: list(v) for k, v in self.blind_spots.items()},
            "total_hits": self.total_hits(),
        }


class ErasureGuardRegistrationError(RuntimeError):
    """The durable re-ingestion guard could not be established."""


@dataclass
class ExecutionReport:
    """What ``execute`` did. ``blind_spots`` carries the sweep's plus the
    execute-side ones (an absent erase or scrub port)."""

    request_id: str
    subject: str
    folder_context: str
    cascade: bool
    dry_run: bool
    sweep: SweepReport
    purged_event_count: int = 0
    purged_pairs: list[str] = field(default_factory=list)
    composite_tombstone_id: str = ""
    forgotten_subject_hash: str = ""
    cascade_manifest: dict[str, dict[str, Any]] = field(default_factory=dict)
    versum_sealed: list[str] = field(default_factory=list)
    decisions_previews_scrubbed: int = 0
    draft_surfaces_redacted: int = 0
    draft_surfaces_deleted: int = 0
    card_files_redacted: int = 0
    card_files_deleted: int = 0
    replayed_noop: bool = False
    pending_erase_queued: list[str] = field(default_factory=list)
    pending_markers: list[dict[str, Any]] = field(default_factory=list)
    blind_spots: dict[str, list[str]] = field(default_factory=dict)
    erasure_mode: str = ""  # two-key | single-key; "" on dry_run
    controller_countersigned: bool = False
    verdict: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "erasure_mode": self.erasure_mode,
            "controller_countersigned": self.controller_countersigned,
            "verdict": self.verdict,
            "request_id": self.request_id,
            "subject": self.subject,
            "folder_context": self.folder_context,
            "cascade": self.cascade,
            "dry_run": self.dry_run,
            "sweep": self.sweep.to_dict(),
            "purged_event_count": self.purged_event_count,
            "purged_pairs": list(self.purged_pairs),
            "composite_tombstone_id": self.composite_tombstone_id,
            "forgotten_subject_hash": self.forgotten_subject_hash,
            "cascade_manifest": dict(self.cascade_manifest),
            "versum_sealed": list(self.versum_sealed),
            "decisions_previews_scrubbed": self.decisions_previews_scrubbed,
            "draft_surfaces_redacted": self.draft_surfaces_redacted,
            "draft_surfaces_deleted": self.draft_surfaces_deleted,
            "card_files_redacted": self.card_files_redacted,
            "card_files_deleted": self.card_files_deleted,
            "replayed_noop": self.replayed_noop,
            "pending_erase_queued": list(self.pending_erase_queued),
            "pending_markers": [dict(m) for m in self.pending_markers],
            "blind_spots": {k: list(v) for k, v in self.blind_spots.items()},
        }


def _validate_subject(subject: str) -> str:
    if not subject or not subject.strip():
        raise ValueError("erasure subject must be non-empty")
    return subject.strip()


def _validate_legal_basis(legal_basis: str) -> None:
    if not legal_basis:
        raise ValueError(
            f"erasure requires legal_basis (one of {sorted(VALID_LEGAL_BASES)})")
    if legal_basis not in VALID_LEGAL_BASES:
        raise ValueError(
            f"unknown legal_basis '{legal_basis}'. Valid: {sorted(VALID_LEGAL_BASES)}")


def _short(text: str, n: int = 120) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "..."


def _redacted_snippet(text: str, subject: str, n: int = 80) -> str:
    """A preview of where the subject fired, every occurrence replaced."""
    if not text:
        return ""
    return _short(scrub_literal(text, subject.strip())[0], n)


def _event_text_haystack(evt: LogEvent, pair: dict | None = None) -> str:
    """Every text field of an event (and its resolved pair body) as one
    string; over-matching is fine for a preview."""
    parts: list[str] = []
    if pair is None:
        pair = resolve_pair(None, evt)
    if isinstance(pair, dict):
        problem = pair.get("problem", {}) or {}
        if isinstance(problem, dict):
            parts.append(str(problem.get("summary", "")))
            facets = problem.get("facets", {}) or {}
            if isinstance(facets, dict):
                for v in facets.values():
                    if isinstance(v, str):
                        parts.append(v)
                    elif isinstance(v, list):
                        parts.extend(item for item in v if isinstance(item, str))
        solution = pair.get("solution", {}) or {}
        if isinstance(solution, dict):
            parts.append(str(solution.get("body", "")))
            parts.extend(s for s in (solution.get("cited_sources", []) or []) if isinstance(s, str))
    if isinstance(evt.extra, dict):
        parts.extend(v for v in evt.extra.values() if isinstance(v, str))
    return "\n".join(parts)


def _classify_kind(evt: LogEvent, pair: dict | None = None) -> str:
    channel = (evt.channel or "").lower()
    if channel == "llm_answer":
        return "capture_llm"
    if channel == "websearch":
        return "capture_web"
    if pair is None:
        pair = resolve_pair(None, evt)
    if isinstance(pair, dict):
        problem = pair.get("problem", {})
        ptype = (problem.get("type") or "").lower() if isinstance(problem, dict) else ""
        if ptype == "llm_exchange":
            return "capture_llm"
        if ptype == "websearch":
            return "capture_web"
        if isinstance(problem, dict) and problem.get("derived_from"):
            return "derived"
    return "pair"


def _logs_for_sweep(
    folder_context: str,
    cascade: bool,
    log_root: Path | None,
    host: Optional[ErasureHost] = None,
    blind_spots: Optional[dict[str, list[str]]] = None,
) -> list[MutationLog]:
    folder = str(Path(folder_context).expanduser().resolve())
    paths = [folder]
    if cascade:
        if host and host.discover_descendants:
            for d in host.discover_descendants(folder, log_root=log_root):
                if d not in paths:
                    paths.append(d)
        elif blind_spots is not None:
            note_blind_spot(blind_spots, "discover_descendants", folder)
    return [MutationLog(p, log_root=log_root) for p in paths]


def _scan_store(
    host: Optional[ErasureHost], port: str, folder: str, subject: str,
    log_root: Path | None, blind_spots: dict[str, list[str]],
) -> Optional[dict[str, Any]]:
    fn = getattr(host, port, None) if host else None
    if fn is None:
        note_blind_spot(blind_spots, port, folder)
        return None
    return fn(folder, subject, log_root=log_root)


def sweep(
    folder_context: str,
    subject: str,
    *,
    cascade: bool = False,
    log_root: Path | None = None,
    host: Optional[ErasureHost] = None,
) -> SweepReport:
    """Every event referencing ``subject`` in the folder (+ descendants), plus
    draft and card files through the host ports. Sealed folders and absent
    ports are named, never reported clean."""
    subject_norm = _validate_subject(subject)
    needle = subject_norm.lower()
    root = Path(folder_context).expanduser().resolve()

    report = SweepReport(
        subject=subject_norm,
        folder_context=str(root),
        cascade=bool(cascade),
        hits_by_kind={"pair": [], "capture_llm": [], "capture_web": [],
                      "derived": [], "draft": [], "card": []},
        hits_by_folder={},
    )
    spots = report.blind_spots
    if not (host and host.pair_from_event):
        note_blind_spot(spots, "pair_from_event")
    if not (host and host.replace_ci):
        note_blind_spot(spots, "replace_ci")

    def _count(folder_str: str) -> None:
        report.hits_by_folder[folder_str] = report.hits_by_folder.get(folder_str, 0) + 1

    for log in _logs_for_sweep(str(root), cascade, log_root, host, spots):
        folder_str = log.folder_path
        for evt in log.replay():
            pair = resolve_pair(host, evt)
            haystack = _event_text_haystack(evt, pair)
            if needle and needle in haystack.lower():
                kind = _classify_kind(evt, pair)
                report.hits_by_kind.setdefault(kind, []).append(SweepHit(
                    folder=folder_str, pair_id=evt.pair_id, kind=kind,
                    audit_id=evt.audit_id,
                    snippet=_redacted_snippet(haystack, subject_norm)))
                _count(folder_str)

        if seal.is_sealed(folder_str, log_root=log_root):
            report.versum_sealed.append(folder_str)

        drafts = _scan_store(host, "scan_drafts", folder_str, subject_norm, log_root, spots)
        if drafts is not None:
            if drafts.get("sealed"):
                report.drafts_sealed.append(folder_str)
            for surface, n in sorted(drafts.get("hits", {}).items()):
                report.hits_by_kind["draft"].append(SweepHit(
                    folder=folder_str, pair_id=f"draft:{surface}", kind="draft",
                    snippet=f"{surface}: {n} occurrence(s)"))
                _count(folder_str)
            for surface in drafts.get("unreadable", []):
                report.hits_by_kind["draft"].append(SweepHit(
                    folder=folder_str, pair_id=f"draft:{surface}", kind="draft",
                    snippet=f"{surface}: unreadable draft file — deleted on execute"))
                _count(folder_str)

        cards = _scan_store(host, "scan_cards", folder_str, subject_norm, log_root, spots)
        if cards is not None:
            if cards.get("sealed"):
                report.cards_sealed.append(folder_str)
            for cid, n in sorted(cards.get("hits", {}).items()):
                report.hits_by_kind["card"].append(SweepHit(
                    folder=folder_str, pair_id=f"card-file:{cid}", kind="card",
                    snippet=f"{n} occurrence(s) in card fields"))
                _count(folder_str)
            for cid in cards.get("identity", []):
                safe, _ = scrub(host, cid, subject_norm)
                report.hits_by_kind["card"].append(SweepHit(
                    folder=folder_str, pair_id=f"card-file:{safe}", kind="card",
                    snippet="card id carries the subject — deleted on execute"))
                _count(folder_str)
            for cid in cards.get("unreadable", []):
                safe, _ = scrub(host, cid, subject_norm)
                report.hits_by_kind["card"].append(SweepHit(
                    folder=folder_str, pair_id=f"card-file:{safe}", kind="card",
                    snippet="unreadable card file — deleted on execute"))
                _count(folder_str)

    pair_ids = sorted({
        h.pair_id for kind, hits in report.hits_by_kind.items()
        if kind not in ("draft", "card") for h in hits
    })
    report.estimated_tombstone = {
        "kind": "erasure_composite",
        "subject_preview": REDACTED,
        "affected_pair_count": len(pair_ids),
        "affected_folder_count": len(report.hits_by_folder),
        "hits_by_kind_count": {k: len(v) for k, v in report.hits_by_kind.items()},
    }
    return report


def dry_run(
    folder_context: str,
    subject: str,
    *,
    cascade: bool = False,
    log_root: Path | None = None,
    host: Optional[ErasureHost] = None,
) -> SweepReport:
    """Alias of :func:`sweep`."""
    return sweep(folder_context, subject, cascade=cascade, log_root=log_root, host=host)


def request(
    folder_context: str,
    subject: str,
    *,
    requester_ref: str,
    reason: str,
    log_root: Path | None = None,
    actor: str = "user",
    host: Optional[ErasureHost] = None,
) -> dict[str, Any]:
    """Write an ``ERASURE_REQUESTED`` event; sweep and purge nothing."""
    subject_norm = _validate_subject(subject)
    if not requester_ref:
        raise ValueError("erasure request requires requester_ref")
    if not reason:
        raise ValueError("erasure request requires reason")
    request_id = "erase-req:" + uuid.uuid4().hex[:16]
    folder = str(Path(folder_context).expanduser().resolve())
    log = MutationLog(folder, log_root=log_root or LOG_ROOT_DEFAULT)
    audit_id = log.append(LogEvent(
        event="system",
        folder_path=folder,
        pair_id=f"erasure:request:{request_id}",
        channel="system",
        actor=actor,
        extra={
            "kind": "ERASURE_REQUESTED",
            "request_id": request_id,
            "requester_ref": requester_ref,
            "reason": scrub(host, reason, subject_norm)[0],
            "subject_preview": REDACTED,
            "subject_length": len(subject_norm),
        },
    ))
    return {"request_id": request_id, "audit_id": audit_id, "folder": folder}


def status(
    folder_context: str,
    request_id: str,
    *,
    log_root: Path | None = None,
) -> dict[str, Any]:
    """Manifest for a request: the request event, the composite, the
    forgotten breadcrumb and every purge stitched through the tracker's ref."""
    folder = str(Path(folder_context).expanduser().resolve())
    log = MutationLog(folder, log_root=log_root or LOG_ROOT_DEFAULT)
    manifest: dict[str, Any] = {
        "request_id": request_id, "folder": folder,
        "requested": None, "executed": None, "purges": [], "forgotten": None,
    }
    tracked_pair_ids: set[str] = set()
    for evt in log.replay():
        extra = evt.extra if isinstance(evt.extra, dict) else {}
        kind = extra.get("kind", "")
        rid = extra.get("request_id", "")
        if kind == "ERASURE_REQUESTED" and rid == request_id:
            manifest["requested"] = {"audit_id": evt.audit_id, "ts": evt.ts, "actor": evt.actor}
        elif kind == "erasure_composite" and rid == request_id:
            manifest["executed"] = {
                "audit_id": evt.audit_id,
                "ts": evt.ts,
                "purged_pair_count": extra.get("affected_pair_count", 0),
                "affected_folder_count": extra.get("affected_folder_count", 0),
                "hits_by_kind_count": extra.get("hits_by_kind_count", {}),
            }
        elif kind == "erasure_pair_purge_start" and (
            extra.get("erasure_request_id") == request_id or rid == request_id
        ):
            # Legacy chains carry the raw id under purged_pair_id on both sides.
            purged_pid = extra.get("purged_pair_ref") or extra.get("purged_pair_id", "")
            if purged_pid:
                tracked_pair_ids.add(purged_pid)
        elif kind == "forgotten_subject_added" and rid == request_id:
            manifest["forgotten"] = {
                "audit_id": evt.audit_id, "ts": evt.ts,
                "subject_hash": extra.get("subject_hash", ""),
            }
    for evt in log.replay():
        if evt.event != "purge" or evt.pair_id not in tracked_pair_ids:
            continue
        extra = evt.extra if isinstance(evt.extra, dict) else {}
        manifest["purges"].append({
            "audit_id": evt.audit_id,
            "ts": evt.ts,
            "pair_id": evt.pair_id,
            "legal_basis": extra.get("legal_basis", ""),
            "purged_event_count": extra.get("purged_event_count", 0),
        })
    return manifest


def _write_forgotten_breadcrumb(root_log, subject_hash, *, request_id, actor) -> None:
    """Best-effort breadcrumb; the ledger itself is already durable."""
    try:
        root_log.append(LogEvent(
            event="system",
            folder_path=root_log.folder_path,
            pair_id=f"forgotten:{subject_hash[:16]}",
            channel="system",
            actor=f"erasure:{actor}",
            extra={
                "kind": "forgotten_subject_added",
                "request_id": request_id,
                "subject_hash": subject_hash,
            },
        ))
    except Exception:
        pass


def _redact_store(
    host: Optional[ErasureHost], port: str, label: str, subject_norm: str,
    folder_context: str, cascade: bool, log_root: Path | None,
    cascade_manifest: dict, affected_folders: set[str], blind_spots: dict[str, list[str]],
) -> tuple[int, int]:
    redacted = deleted = 0
    fn = getattr(host, port, None) if host else None
    for log in _logs_for_sweep(folder_context, cascade, log_root, host):
        folder = log.folder_path
        if fn is None:
            note_blind_spot(blind_spots, port, folder)
            continue
        try:
            res = fn(folder, subject_norm, log_root=log_root)
        except Exception as e:  # pragma: no cover - surfaces in report
            cascade_manifest.setdefault(folder, {}).setdefault("errors", []).append(
                {label: scrub(host, f"{type(e).__name__}: {e}", subject_norm)[0]})
            continue
        if not res.get("ok"):
            cascade_manifest.setdefault(folder, {}).setdefault("errors", []).append(
                {label: res.get("error", "refused")})
            continue
        if res["redacted"] or res["deleted"]:
            cascade_manifest.setdefault(folder, {})[label] = {
                "redacted": dict(res["redacted"]),
                "deleted": [scrub(host, c, subject_norm)[0] for c in res["deleted"]],
            }
            redacted += len(res["redacted"])
            deleted += len(res["deleted"])
            affected_folders.add(folder)
    return redacted, deleted


def execute(
    folder_context: str,
    subject: str,
    *,
    legal_basis: str,
    requester_ref: str,
    reason: str,
    controller_signer: Any = None,
    cascade: bool = False,
    dry_run: bool = False,
    log_root: Path | None = None,
    actor: str = "user",
    request_id: str | None = None,
    queue_if_sealed: bool = False,
    host: Optional[ErasureHost] = None,
    require_controller: bool = False,
) -> ExecutionReport:
    """Sweep → guard → per-pair purge → composite tombstone → ledger.

    ``controller_signer`` is accepted for signature symmetry; the chain's
    ``purge`` co-signs with the controller key when one exists (two-key) and
    otherwise signs with the operator key alone (single-key), recording
    ``erasure_mode`` on the tombstone and ``controller_countersigned`` on the
    report. Both modes purge, so both carry the releasing verdict.
    ``require_controller=True`` turns a missing controller key into
    :class:`ControllerKeyMissingError` before anything is written — the one
    execute that is ``refused``. ``queue_if_sealed`` arms a
    pending marker for a sealed root instead of raising ``SealedWriteError``
    (feature flag required); sealed descendants are always queued when the
    feature is on. Absent host ports are named in ``blind_spots``.
    """
    subject_norm = _validate_subject(subject)
    _validate_legal_basis(legal_basis)
    if not requester_ref:
        raise ValueError("erasure execute requires requester_ref")
    if not reason:
        raise ValueError("erasure execute requires reason")
    controller_present = signing.public_controller_key_fingerprint() is not None
    if require_controller and not controller_present:
        raise ControllerKeyMissingError(
            "erasure execute requires a controller key; none is registered")
    if not request_id:
        request_id = "erase-req:" + uuid.uuid4().hex[:16]

    reason_safe = scrub(host, reason, subject_norm)[0]

    sweep_report = sweep(folder_context, subject_norm, cascade=cascade,
                         log_root=log_root, host=host)
    report = ExecutionReport(
        request_id=request_id,
        subject=REDACTED,
        folder_context=sweep_report.folder_context,
        cascade=cascade,
        dry_run=dry_run,
        sweep=sweep_report,
    )
    report.versum_sealed = sorted(set(sweep_report.versum_sealed))
    report.blind_spots = {k: list(v) for k, v in sweep_report.blind_spots.items()}
    spots = report.blind_spots

    sealed_to_arm: list[str] = []
    root_ctx = sweep_report.folder_context
    if pending_erase.feature_enabled():
        sealed_in_scope = pending_erase.discover_sealed_in_scope(
            root_ctx, cascade=cascade, log_root=log_root)
        sealed_to_arm = [f for f in sealed_in_scope if f != root_ctx or queue_if_sealed]
    report.sweep.pending_erase_queued = sorted(sealed_to_arm)
    report.verdict = verdict_for("dry_run" if dry_run else "execute",
                                 controller_present=controller_present,
                                 require_controller=require_controller)

    if dry_run:
        return report
    report.erasure_mode = "two-key" if controller_present else "single-key"
    report.controller_countersigned = controller_present

    try:
        subject_hash, guard_added = forgotten_subjects.ensure(
            sweep_report.folder_context, subject_norm, request_id=request_id)
    except Exception as exc:
        raise ErasureGuardRegistrationError(
            "forgotten-subject guard could not be durably registered; "
            "erasure not started") from exc
    report.forgotten_subject_hash = subject_hash
    was_already_forgotten = not guard_added

    root_marker_armed = False
    for sealed_folder in sealed_to_arm:
        try:
            marker = pending_erase.arm_marker(
                sealed_folder, subject_norm=subject_norm, request_id=request_id,
                legal_basis=legal_basis, requester_ref=requester_ref,
                reason_safe=reason_safe, log_root=log_root)
        except Exception as exc:
            _record_drop("erasure.execute:arm_marker", exc, request_id=request_id, log_root=log_root)
            if sealed_folder not in report.versum_sealed:
                report.versum_sealed.append(sealed_folder)
            continue
        report.pending_erase_queued.append(sealed_folder)
        report.pending_markers.append({
            "folder": sealed_folder,
            "marker_id": marker["marker_id"],
            "controller_keyid": marker["controller_keyid"],
        })
        if sealed_folder == root_ctx:
            root_marker_armed = True
    report.pending_erase_queued = sorted(set(report.pending_erase_queued))
    report.versum_sealed = sorted(set(report.versum_sealed))

    cascade_manifest: dict[str, dict[str, Any]] = {}
    affected_pair_ids: set[str] = set()
    per_folder_pairs: dict[str, set[str]] = {}
    for kind, hits in sweep_report.hits_by_kind.items():
        if kind in ("draft", "card"):
            continue
        for h in hits:
            affected_pair_ids.add(h.pair_id)
            per_folder_pairs.setdefault(h.folder, set()).add(h.pair_id)

    total_purged = 0
    purged_pairs_list: list[str] = []
    affected_pair_refs: set[str] = set()
    purge_reason = f"[erase-req:{request_id}] {reason_safe}"
    for folder, pair_ids in per_folder_pairs.items():
        log = MutationLog(folder, log_root=log_root or LOG_ROOT_DEFAULT)
        per_folder: dict[str, Any] = {"purged_pair_count": 0, "purged_event_count": 0, "pairs": []}
        purged_pids_this_folder: set[str] = set()
        for pid in sorted(pair_ids):
            # The tracker names the pair by its opaque ref and lives under a
            # derived pair_id so the purge it announces cannot wipe it.
            ref = forgotten_subjects.purged_pair_ref(folder, pid)
            affected_pair_refs.add(ref)
            try:
                log.append(LogEvent(
                    event="system",
                    folder_path=folder,
                    pair_id=f"erasure-track:{request_id}:{ref}",
                    channel="system",
                    actor=f"erasure:{actor}",
                    extra={
                        "kind": "erasure_pair_purge_start",
                        "request_id": request_id,
                        "erasure_request_id": request_id,
                        "purged_pair_ref": ref,
                        "subject_preview": REDACTED,
                    },
                ))
            except Exception as exc:
                _record_drop("erasure.execute:purge_start", exc,
                             request_id=request_id, log_root=log_root)
            try:
                n = log.purge(pid, legal_basis=legal_basis,
                              requester_ref=requester_ref, reason=purge_reason)
            except Exception as e:  # pragma: no cover - surfaces in report
                per_folder.setdefault("errors", []).append(
                    {"pair_id": pid, "error": f"{type(e).__name__}: {e}"})
                continue
            per_folder["purged_event_count"] += int(n)
            per_folder["purged_pair_count"] += 1 if n else 0
            per_folder["pairs"].append(pid)
            if n:
                total_purged += int(n)
                purged_pairs_list.append(pid)
                purged_pids_this_folder.add(pid)

        if purged_pids_this_folder:
            if host and host.erase_versum_mirror:
                versum_errors, versum_sealed_here = host.erase_versum_mirror(
                    folder, purged_pids_this_folder, physical=True,
                    reason=purge_reason, actor=actor, log_root=log_root)
                for verr in versum_errors:
                    per_folder.setdefault("errors", []).append(
                        {"versum_purge": f"{type(verr).__name__}: {verr}"})
                    _record_drop("erasure.execute:versum_purge", verr,
                                 request_id=request_id, log_root=log_root)
                for sf in versum_sealed_here:
                    if sf not in report.versum_sealed:
                        report.versum_sealed.append(sf)
                    cascade_manifest.setdefault(sf, {})["versum_sealed"] = True
            else:
                note_blind_spot(spots, "erase_versum_mirror", folder)
                per_folder["versum_blind_spot"] = True
        cascade_manifest.setdefault(folder, {}).update(per_folder)

    affected_folders: set[str] = set(per_folder_pairs)
    drafts_redacted, drafts_deleted = _redact_store(
        host, "redact_drafts", "drafts", subject_norm, sweep_report.folder_context,
        cascade, log_root, cascade_manifest, affected_folders, spots)
    report.draft_surfaces_redacted = drafts_redacted
    report.draft_surfaces_deleted = drafts_deleted
    cards_redacted, cards_deleted = _redact_store(
        host, "redact_cards", "cards", subject_norm, sweep_report.folder_context,
        cascade, log_root, cascade_manifest, affected_folders, spots)
    report.card_files_redacted = cards_redacted
    report.card_files_deleted = cards_deleted

    report.purged_event_count = total_purged
    report.purged_pairs = sorted(affected_pair_ids)
    report.cascade_manifest = cascade_manifest

    # Delivery is at-least-once: a replay that purged nothing new must skip the
    # non-idempotent composite / ledger / breadcrumb writes.
    had_effect = bool(
        total_purged or drafts_redacted or drafts_deleted
        or cards_redacted or cards_deleted or report.pending_erase_queued)

    if root_marker_armed:
        # The root is sealed; ``apply_markers`` writes the equivalent
        # ``erasure_pending_applied`` record on unseal.
        pass
    elif was_already_forgotten and not had_effect:
        report.replayed_noop = True
    else:
        root_log = MutationLog(sweep_report.folder_context, log_root=log_root or LOG_ROOT_DEFAULT)
        composite_id = "erase-composite:" + uuid.uuid4().hex[:16]
        root_log.append(LogEvent(
            event="system",
            folder_path=sweep_report.folder_context,
            pair_id=composite_id,
            channel="system",
            actor=f"erasure:{actor}",
            extra={
                "kind": "erasure_composite",
                "request_id": request_id,
                "legal_basis": legal_basis,
                "requester_ref": requester_ref,
                "reason": reason_safe,
                "subject_preview": REDACTED,
                "subject_length": len(subject_norm),
                "affected_pair_count": len(affected_pair_ids),
                "affected_folder_count": len(affected_folders),
                "purged_event_count": total_purged,
                "purged_pair_refs": sorted(affected_pair_refs),
                "hits_by_kind_count": {k: len(v) for k, v in sweep_report.hits_by_kind.items()},
                "draft_surfaces_redacted": drafts_redacted,
                "draft_surfaces_deleted": drafts_deleted,
                "card_files_redacted": cards_redacted,
                "card_files_deleted": cards_deleted,
                "blind_spots": sorted(spots),
                "cascade": bool(cascade),
            },
        ))
        report.composite_tombstone_id = composite_id
        if guard_added:
            _write_forgotten_breadcrumb(root_log, subject_hash, request_id=request_id, actor=actor)

    try:
        from loomground_lock.decisions import DecisionsStore
        report.decisions_previews_scrubbed = DecisionsStore().erase_subject(subject_norm)
    except Exception as exc:
        _record_drop("erasure.execute:decisions_scrub", exc, log_root=log_root)

    report.versum_sealed = sorted(set(report.versum_sealed))
    return report


EraseGuardHit = forgotten_subjects.EraseGuardHit


__all__ = [
    "STATES",
    "ControllerKeyMissingError",
    "EraseGuardHit",
    "ErasureGuardRegistrationError",
    "ErasureHost",
    "ExecutionReport",
    "SweepHit",
    "SweepReport",
    "dry_run",
    "execute",
    "request",
    "status",
    "sweep",
    "verdict_for",
]
