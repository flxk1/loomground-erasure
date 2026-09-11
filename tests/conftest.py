# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Hermetic suite. HOME, USERPROFILE, WORKSPACE_KEY_DIR and the audit-drop
root are redirected into the session temp tree at configure time, before the
package is first imported (``signing.DEFAULT_KEY_DIR`` and the chain's
``LOG_ROOT_DEFAULT`` derive from ``Path.home()`` at import); every
``*_LOG_ROOT`` override is dropped so the chain root resolves under that
home. Signing keys and seals never land in the real ``~/.workspace``."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from _pytest.tmpdir import TempPathFactory


def pytest_configure(config):
    factory = TempPathFactory.from_config(config, _ispytest=True)
    home = os.path.realpath(str(factory.mktemp("home", numbered=True)))
    os.environ["HOME"] = home
    os.environ["USERPROFILE"] = home
    os.environ["WORKSPACE_KEY_DIR"] = os.path.join(home, "keys")
    os.environ["WORKSPACE_L0_LOG_ROOT"] = os.path.join(home, "audit-drops")
    os.environ["WORKSPACES_ALLOW_UNREGISTERED"] = "1"
    for name in [k for k in os.environ if k.endswith("_LOG_ROOT") and k != "WORKSPACE_L0_LOG_ROOT"]:
        os.environ.pop(name, None)
    for name in ("WORKSPACE_PENDING_ERASE", "WORKSPACE_KEY_PINNING",
                 "WORKSPACE_STRICT_KEY_PINNING", "WORKSPACE_STRICT_HOST_DIVERGENCE",
                 "WORKSPACE_KEY_PASSPHRASE", "WORKSPACE_HOST_ID", "WORKSPACE_KEY_PIN_DIR",
                 "WORKSPACE_FOLDER_CONTEXT"):
        os.environ.pop(name, None)
    os.makedirs(os.environ["WORKSPACE_KEY_DIR"], exist_ok=True)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Each test: its own key dir, feature flag off, no lock host wired."""
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("WORKSPACES_ALLOW_UNREGISTERED", "1")
    monkeypatch.delenv("WORKSPACE_PENDING_ERASE", raising=False)
    from loomground_lock import host_deps
    host_deps.clear()
    yield
    host_deps.clear()


@pytest.fixture
def isolated_env(tmp_path):
    """Per-test log root + workspace; operator and controller keys generated."""
    from loomground_audit_chain import signing
    log_root = tmp_path / "logs"
    log_root.mkdir(parents=True, exist_ok=True)
    signing.ensure_keypair()
    signing.ensure_controller_keypair()
    workspace = tmp_path / "ws"
    workspace.mkdir(parents=True, exist_ok=True)
    return {"log_root": log_root, "workspace": workspace, "tmp_path": tmp_path}


def seed_pair(workspace, log_root, *, pair_id, summary, body="",
              channel="document", problem_type="case"):
    """An ingest event whose embedded pair carries the given text."""
    from loomground_audit_chain.mutation_log import LogEvent, MutationLog
    log = MutationLog(workspace, log_root=log_root)
    pair = {
        "id": pair_id,
        "problem": {"id": "sha256:problem-" + pair_id[-8:], "summary": summary,
                    "type": problem_type, "facets": {}},
        "solution": {"id": pair_id, "problem_id": "sha256:problem-" + pair_id[-8:],
                     "body": body, "body_format": "prose" if body else "metadata",
                     "authority_tier": 5, "confidence": 0.5, "cited_sources": [],
                     "extractor_chain": ["test:seed"]},
    }
    log.append(LogEvent(
        event="ingest", folder_path=str(workspace), pair_id=pair_id,
        lifecycle_state="live", channel=channel, actor="test",
        extra={"pair": pair, "distribution_scope": "private"},
    ))
    return pair_id


def chain_descendants(folder, *, log_root=None):
    """A host's folder walk: every folder with a log under ``log_root`` that
    is ``folder`` or a path-descendant of it."""
    from loomground_audit_chain.mutation_log import LOG_ROOT_DEFAULT
    root = Path(log_root) if log_root else LOG_ROOT_DEFAULT
    ctx = str(Path(folder).expanduser().resolve())
    prefix = ctx if ctx.endswith("/") else ctx + "/"
    out: list[str] = []
    if not root.exists():
        return out
    for subdir in sorted(root.iterdir()):
        log_file = subdir / "events.jsonl"
        if not log_file.exists():
            continue
        for line in log_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                fp = json.loads(line).get("folder_path")
            except json.JSONDecodeError:
                continue
            if fp and (fp == ctx or str(fp).startswith(prefix)) and fp not in out:
                out.append(str(fp))
            break
    return sorted(out)


class FileStore:
    """In-memory stand-in for a host's draft or card store: ``{folder: {name: text}}``."""

    def __init__(self, kind: str):
        self.kind = kind
        self.files: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[str, str]] = []

    def put(self, folder, name, text):
        self.files.setdefault(str(Path(folder).resolve()), {})[name] = text

    def scan(self, folder, subject, *, log_root=None):
        self.calls.append(("scan", str(folder)))
        pat = re.compile(re.escape(subject), re.IGNORECASE)
        hits = {n: len(pat.findall(t)) for n, t in self.files.get(str(folder), {}).items()
                if pat.search(t)}
        out = {"hits": hits, "unreadable": [], "sealed": False}
        if self.kind == "cards":
            out["identity"] = [n for n in self.files.get(str(folder), {}) if pat.search(n)]
        return out

    def redact(self, folder, subject, *, log_root=None):
        self.calls.append(("redact", str(folder)))
        pat = re.compile(re.escape(subject), re.IGNORECASE)
        redacted: dict[str, int] = {}
        deleted: list[str] = []
        for name, text in list(self.files.get(str(folder), {}).items()):
            if self.kind == "cards" and pat.search(name):
                deleted.append(name)
                del self.files[str(folder)][name]
                continue
            new, n = pat.subn("[REDACTED]", text)
            if n:
                self.files[str(folder)][name] = new
                redacted[name] = n
        return {"ok": True, "redacted": redacted, "deleted": deleted}


class VersumRecorder:
    """Records ``erase_versum_mirror`` calls; erases nothing itself."""

    def __init__(self):
        self.calls: list[tuple[str, set[str], dict]] = []

    def __call__(self, folder, pair_ids, *, physical, reason, actor, log_root):
        self.calls.append((str(folder), set(pair_ids),
                           {"physical": physical, "reason": reason, "actor": actor}))
        return [], []


@pytest.fixture
def full_host():
    """Every port bound to a recording fake."""
    from loomground_erasure import ErasureHost
    drafts, cards, versum = FileStore("drafts"), FileStore("cards"), VersumRecorder()

    def replace_ci(text, needle):
        return re.compile(re.escape(needle), re.IGNORECASE).subn("[REDACTED]", text)

    host = ErasureHost(
        pair_from_event=lambda evt: evt.extra.get("pair") if isinstance(evt.extra, dict) else None,
        discover_descendants=chain_descendants,
        replace_ci=replace_ci,
        scan_drafts=drafts.scan, redact_drafts=drafts.redact,
        scan_cards=cards.scan, redact_cards=cards.redact,
        erase_versum_mirror=versum,
    )
    host.fakes = {"drafts": drafts, "cards": cards, "versum": versum}  # type: ignore[attr-defined]
    return host
