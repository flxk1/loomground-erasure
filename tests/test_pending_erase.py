# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Pending-erasure markers against a SEALED folder. Every test sets
``WORKSPACE_PENDING_ERASE=1`` explicitly. The top probe is erase-injection:
a filesystem writer who can reach the sealed-blob directory must never make
``unseal`` delete what nobody asked to erase — every bad-marker test asserts
the unseal raises AND nothing was restored or deleted."""
from __future__ import annotations

import json

import pytest

from loomground_audit_chain import signing
from loomground_audit_chain.mutation_log import MutationLog, SealedWriteError
from loomground_erasure import ErasureHost, bind_seal_hooks, erasure, pending_erase
from loomground_lock import seal
from loomground_workspace.workspace_registry import add_known_workspace

from conftest import VersumRecorder, chain_descendants, seed_pair


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Feature ON, both keys, hooks bound with a versum recorder."""
    monkeypatch.setenv("WORKSPACE_PENDING_ERASE", "1")
    signing.ensure_keypair()
    signing.ensure_controller_keypair()
    versum = VersumRecorder()
    host = ErasureHost(discover_descendants=chain_descendants, erase_versum_mirror=versum)
    bind_seal_hooks(host)
    return {"log_root": tmp_path / "logs", "host": host, "versum": versum}


@pytest.fixture
def env_operator_only(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_PENDING_ERASE", "1")
    signing.ensure_keypair()
    host = ErasureHost(discover_descendants=chain_descendants)
    bind_seal_hooks(host)
    return {"log_root": tmp_path / "logs", "host": host}


def _chain_pair_ids(folder, log_root) -> set[str]:
    return {evt.pair_id for evt in MutationLog(str(folder), log_root=log_root).replay()}


def _read_ledger(folder, log_root) -> list[dict]:
    p = pending_erase._marker_ledger_path(str(folder), log_root)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def _write_ledger(folder, log_root, markers: list[dict]) -> None:
    pending_erase._marker_ledger_path(str(folder), log_root).write_text(
        "".join(json.dumps(m) + "\n" for m in markers))


def _execute(env, folder, subject, **kw):
    return erasure.execute(str(folder), subject, legal_basis="art_17_1_a",
                           requester_ref="ticket-1", reason="test",
                           log_root=env["log_root"], host=env["host"], **kw)


def _seed(folder, log_root, pid, summary, body):
    seed_pair(folder, log_root, pair_id=pid, summary=summary, body=body)


def _seal_and_arm(env, tmp_path, subject="ForgedSubjXyz"):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    pid = "sha256:target-1"
    _seed(folder, log_root, pid, f"Notes about {subject}", f"{subject}'s file")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    _execute(env, folder, subject, queue_if_sealed=True)
    return folder, log_root, pid


def test_arm_seal_unseal_applies_erasure(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    jane_id, other_id = "sha256:jane-1", "sha256:other-1"
    _seed(folder, log_root, jane_id, "Notes about JaneUniqueSubj42", "JaneUniqueSubj42's file.")
    _seed(folder, log_root, other_id, "Notes about someone else", "totally unrelated body")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)

    report = _execute(env, folder, "JaneUniqueSubj42", queue_if_sealed=True)
    assert report.pending_erase_queued == [str(folder.resolve())]
    assert len(report.pending_markers) == 1
    assert report.pending_markers[0]["controller_keyid"] is not None
    assert report.composite_tombstone_id == ""
    assert len(_read_ledger(folder, log_root)) == 1

    result = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert result["unsealed"] is True
    applied = result["pending_erase_applied"]
    assert applied["purged_pair_count"] == 1
    assert applied["purged_event_count"] >= 1
    assert applied["errors"] == []
    assert applied["blind_spots"] == {"redact_drafts": [str(folder)], "redact_cards": [str(folder)]}
    assert env["versum"].calls[0][0] == str(folder) and env["versum"].calls[0][1] == {jane_id}

    assert jane_id not in _chain_pair_ids(folder, log_root)
    assert other_id in _chain_pair_ids(folder, log_root)
    kinds = [evt.extra.get("kind") for evt in MutationLog(str(folder), log_root=log_root).replay()]
    assert "erasure_pending_applied" in kinds
    assert _read_ledger(folder, log_root) == []
    assert not seal.is_sealed(folder, log_root=log_root)


def test_forged_body_field_fails_closed(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path)
    markers = _read_ledger(folder, log_root)
    markers[0]["subject_hash"] = "0" * 64
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)
    assert len(_read_ledger(folder, log_root)) == 1


def test_forged_operator_signature_fails_closed(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path)
    markers = _read_ledger(folder, log_root)
    markers[0]["operator_sig"] = "ff" * 64
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)


def test_missing_controller_signature_when_claimed_fails_closed(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path)
    markers = _read_ledger(folder, log_root)
    assert markers[0]["controller_keyid"] is not None
    markers[0]["controller_sig"] = ""
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)


def test_forged_controller_signature_fails_closed(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path)
    markers = _read_ledger(folder, log_root)
    markers[0]["controller_sig"] = "ab" * 64
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)


def test_forged_subject_token_count_fails_closed(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path, subject="TokCountSubjKlm")
    markers = _read_ledger(folder, log_root)
    assert markers[0]["subject_token_count"] == 1
    markers[0]["subject_token_count"] = 99
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)
    assert len(_read_ledger(folder, log_root)) == 1


def test_stripped_marker_is_safe_by_omission(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path, subject="StrippedSubjQrs")
    _write_ledger(folder, log_root, [])
    result = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert result["unsealed"] is True
    assert "pending_erase_applied" not in result
    assert pid in _chain_pair_ids(folder, log_root)
    assert not seal.is_sealed(folder, log_root=log_root)


def test_moved_marker_wrong_folder_hash_is_rejected(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path, subject="MovedSubjLmn")
    markers = _read_ledger(folder, log_root)
    markers[0]["folder_hash"] = "not-this-folder-0123456789abcdef01234567"
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)


def test_replayed_marker_stale_blob_fingerprint_is_rejected(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path, subject="ReplaySubjOpq")
    markers = _read_ledger(folder, log_root)
    markers[0]["sealed_blob_fingerprint"] = "0" * 64
    _write_ledger(folder, log_root, markers)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)


def test_apply_markers_converges_on_replay(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path, subject="IdemSubjTuv")
    marker = _read_ledger(folder, log_root)[0]
    first = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)["pending_erase_applied"]
    assert first["purged_pair_count"] == 1
    assert pid not in _chain_pair_ids(folder, log_root)
    second = pending_erase.apply_markers(str(folder), [marker], log_root=log_root, host=env["host"])
    assert second["purged_pair_count"] == 0
    assert second["purged_event_count"] == 0
    assert second["errors"] == []
    assert pid not in _chain_pair_ids(folder, log_root)


def test_apply_markers_without_host_names_every_absent_port(env, tmp_path):
    folder, log_root, pid = _seal_and_arm(env, tmp_path, subject="NoHostSubjAbc")
    marker = _read_ledger(folder, log_root)[0]
    from loomground_lock import host_deps
    host_deps.clear()
    result = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert "pending_erase_applied" not in result  # unwired lock hooks: markers untouched
    assert len(_read_ledger(folder, log_root)) == 1
    applied = pending_erase.apply_markers(str(folder), [marker], log_root=log_root)
    assert applied["purged_pair_count"] == 1
    assert applied["blind_spots"] == {
        "erase_versum_mirror": [str(folder)],
        "redact_drafts": [str(folder)],
        "redact_cards": [str(folder)],
    }
    assert _read_ledger(folder, log_root) == []


def test_recall_gap_token_caught_embedded_missed(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    subject = "Doe123uniquemarker"
    _seed(folder, log_root, "sha256:standalone-1", "case notes", f"Notes about {subject} are attached.")
    _seed(folder, log_root, "sha256:embedded-1", "unrelated ticket",
          f"See ticket prefix{subject}suffix for details.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    _execute(env, folder, subject, queue_if_sealed=True)
    seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    remaining = _chain_pair_ids(folder, log_root)
    assert "sha256:standalone-1" not in remaining
    assert "sha256:embedded-1" in remaining  # documented recall gap: mid-word embedding


def test_multiword_subject_ngram_recalled_start_end_and_multiple(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    _seed(folder, log_root, "sha256:ngram-start", "case notes", "Jane Doe called about the case.")
    _seed(folder, log_root, "sha256:ngram-end", "case notes", "Please follow up with Jane Doe")
    _seed(folder, log_root, "sha256:ngram-multi", "case notes",
          "Jane Doe emailed early. Later, Jane Doe called again.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    report = _execute(env, folder, "Jane Doe", queue_if_sealed=True)
    assert report.pending_erase_queued == [str(folder.resolve())]
    seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    remaining = _chain_pair_ids(folder, log_root)
    assert not {"sha256:ngram-start", "sha256:ngram-end", "sha256:ngram-multi"} & remaining


def test_multiword_subject_ngram_does_not_over_erase(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    _seed(folder, log_root, "sha256:ngram-non-adjacent", "case notes",
          "Jane will call, and separately Doe will follow up.")
    _seed(folder, log_root, "sha256:ngram-partial", "case notes", "Jane went to the store.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    _execute(env, folder, "Jane Doe", queue_if_sealed=True)
    seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    remaining = _chain_pair_ids(folder, log_root)
    assert {"sha256:ngram-non-adjacent", "sha256:ngram-partial"} <= remaining


@pytest.mark.parametrize("subject,text", [
    ("O'Brien", "I spoke with O'Brien yesterday about the matter."),
    ("Smith, John", "Received a file from Smith, John re: the claim."),
])
def test_punctuated_subject_is_recalled(env, tmp_path, subject, text):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    _seed(folder, log_root, "sha256:punct-hit", "intake", text)
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    report = _execute(env, folder, subject, queue_if_sealed=True)
    assert report.pending_erase_queued == [str(folder.resolve())]
    seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert "sha256:punct-hit" not in _chain_pair_ids(folder, log_root)


def test_punctuated_subject_does_not_over_erase(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    _seed(folder, log_root, "sha256:punct-partial", "unrelated", "Smith called about a different matter.")
    _seed(folder, log_root, "sha256:punct-non-adjacent", "unrelated",
          "Smith will follow up, and separately John will too.")
    _seed(folder, log_root, "sha256:punct-unrelated", "unrelated", "Totally unrelated record about Jane Doe.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    _execute(env, folder, "Smith, John", queue_if_sealed=True)
    seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    remaining = _chain_pair_ids(folder, log_root)
    assert {"sha256:punct-partial", "sha256:punct-non-adjacent", "sha256:punct-unrelated"} <= remaining


def test_repeated_execute_dedupes_to_one_marker(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    pid = "sha256:dedup-1"
    _seed(folder, log_root, pid, "Notes about DedupSubjGhi", "DedupSubjGhi's file.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    r1 = _execute(env, folder, "DedupSubjGhi", queue_if_sealed=True, request_id="req-a")
    r2 = _execute(env, folder, "DedupSubjGhi", queue_if_sealed=True, request_id="req-b")
    r3 = _execute(env, folder, "DedupSubjGhi", queue_if_sealed=True)
    assert len(_read_ledger(folder, log_root)) == 1
    assert (r1.pending_markers[0]["marker_id"] == r2.pending_markers[0]["marker_id"]
            == r3.pending_markers[0]["marker_id"])
    result = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert result["pending_erase_applied"]["purged_pair_count"] == 1
    assert pid not in _chain_pair_ids(folder, log_root)


def test_sealed_descendant_cascade_end_to_end(env, tmp_path):
    log_root = env["log_root"]
    root = tmp_path / "root"
    child = root / "child"
    child.mkdir(parents=True)
    add_known_workspace(str(root), log_root=log_root)
    add_known_workspace(str(child), log_root=log_root)
    pid = "sha256:child-jane"
    _seed(child, log_root, pid, "Notes about CascadeSubjIjk", "CascadeSubjIjk's file in the child.")
    seal.seal_folder(child, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(child, log_root=log_root) and not seal.is_sealed(root, log_root=log_root)
    report = _execute(env, root, "CascadeSubjIjk", cascade=True)
    assert report.pending_erase_queued == [str(child.resolve())]
    assert len(report.pending_markers) == 1
    assert report.composite_tombstone_id != ""
    result = seal.unseal_folder(child, passphrase="pw", log_root=log_root)
    assert result["pending_erase_applied"]["purged_pair_count"] == 1
    assert pid not in _chain_pair_ids(child, log_root)


def test_discover_sealed_in_scope_reaches_registered_descendants_only(env, tmp_path):
    log_root = env["log_root"]
    root = tmp_path / "root"
    known, unknown = root / "known", root / "unknown"
    known.mkdir(parents=True)
    unknown.mkdir(parents=True)
    add_known_workspace(str(known), log_root=log_root)
    for f in (known, unknown):
        _seed(f, log_root, "sha256:x", "x", "x")
        seal.seal_folder(f, passphrase="pw", log_root=log_root)
    assert pending_erase.discover_sealed_in_scope(str(root), cascade=True, log_root=log_root) == [
        str(known.resolve())]
    assert pending_erase.discover_sealed_in_scope(str(root), cascade=False, log_root=log_root) == []
    with pytest.raises(pending_erase.PendingEraseError):
        pending_erase.arm_marker(str(root), subject_norm="x", request_id="r", legal_basis="art_17_1_a",
                                 requester_ref="q", reason_safe="t", log_root=log_root)


def test_operator_only_fallback_arms_and_applies(env_operator_only, tmp_path):
    env = env_operator_only
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    assert signing.public_controller_key_fingerprint() is None
    pid = "sha256:l0-jane"
    _seed(folder, log_root, pid, "Notes about L0SubjWxy", "L0SubjWxy's file.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    report = _execute(env, folder, "L0SubjWxy", queue_if_sealed=True)
    assert report.pending_erase_queued == [str(folder.resolve())]
    assert report.pending_markers[0]["controller_keyid"] is None
    ledger = _read_ledger(folder, log_root)
    assert ledger[0]["controller_sig"] == "" and ledger[0]["operator_sig"]
    result = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert result["pending_erase_applied"]["purged_pair_count"] == 1
    assert pid not in _chain_pair_ids(folder, log_root)


def test_default_still_raises_sealed_write_error_on_root(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    _seed(folder, log_root, "sha256:default-jane", "Notes about DefaultSubjAbc", "DefaultSubjAbc's file.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    with pytest.raises(SealedWriteError):
        _execute(env, folder, "DefaultSubjAbc")
    assert _read_ledger(folder, log_root) == []
    assert seal.is_sealed(folder, log_root=log_root)


def test_queue_if_sealed_true_queues_instead_of_raising(env, tmp_path):
    log_root = env["log_root"]
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    pid = "sha256:queued-jane"
    _seed(folder, log_root, pid, "Notes about QueuedSubjDef", "QueuedSubjDef's file.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    report = _execute(env, folder, "QueuedSubjDef", queue_if_sealed=True)
    assert report.pending_erase_queued == [str(folder.resolve())]
    assert report.composite_tombstone_id == ""
    result = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert result["pending_erase_applied"]["purged_pair_count"] == 1
    assert pid not in _chain_pair_ids(folder, log_root)


def test_feature_flag_off_arms_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("WORKSPACE_PENDING_ERASE", raising=False)
    signing.ensure_keypair()
    signing.ensure_controller_keypair()
    assert pending_erase.feature_enabled() is False
    log_root = tmp_path / "logs"
    folder = tmp_path / "ws"
    folder.mkdir()
    add_known_workspace(str(folder), log_root=log_root)
    _seed(folder, log_root, "sha256:flagoff-jane", "Notes about FlagOffSubj", "FlagOffSubj's file.")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    with pytest.raises(SealedWriteError):
        erasure.execute(str(folder), "FlagOffSubj", legal_basis="art_17_1_a", requester_ref="t1",
                        reason="test", log_root=log_root, queue_if_sealed=True)
    assert _read_ledger(folder, log_root) == []
