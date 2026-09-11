# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The three-state protocol: request → sweep (dry_run) → execute → status,
over a chain with generated operator + controller keys, through injected
host ports; absent ports are named blind spots."""
from __future__ import annotations

import json

import pytest

from loomground_audit_chain import mutation_log, signing
from loomground_audit_chain.mutation_log import LogEvent, MutationLog, VALID_LEGAL_BASES
from loomground_erasure import ErasureHost, erasure, forgotten_subjects
from loomground_lock import seal

from conftest import chain_descendants, seed_pair


def _execute(env, subject="Jane Doe", **kw):
    kw.setdefault("legal_basis", "art_17_1_a")
    kw.setdefault("requester_ref", "req:t")
    kw.setdefault("reason", "t")
    return erasure.execute(str(env["workspace"]), subject, log_root=env["log_root"], **kw)


def test_sweep_finds_pair_text_match(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:hit", summary="Notes about Jane Doe's contract",
              body="The agreement with Jane Doe covers 2025.")
    seed_pair(ws, lr, pair_id="sha256:miss", summary="Unrelated note", body="Q3 revenue overview.")
    report = erasure.sweep(str(ws), "Jane Doe", log_root=lr)
    assert report.total_hits() >= 1
    pair_ids = {h.pair_id for h in report.hits_by_kind["pair"]}
    assert "sha256:hit" in pair_ids and "sha256:miss" not in pair_ids
    assert all("Jane Doe" not in h.snippet for h in report.hits_by_kind["pair"])
    assert report.estimated_tombstone["subject_preview"] == "[REDACTED]"


def test_sweep_finds_capture_llm_match(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:llm-1", summary="exchange",
              body="Subject Jane Doe was discussed.", channel="llm_answer",
              problem_type="llm_exchange")
    report = erasure.sweep(str(ws), "Jane Doe", log_root=lr)
    assert any(h.pair_id == "sha256:llm-1" for h in report.hits_by_kind["capture_llm"])


def test_sweep_finds_capture_web_match(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:web-1", summary="web search: Jane Doe",
              body="Result 1: Jane Doe biography ...", channel="websearch",
              problem_type="websearch")
    report = erasure.sweep(str(ws), "Jane Doe", log_root=lr)
    assert any(h.pair_id == "sha256:web-1" for h in report.hits_by_kind["capture_web"])


def test_sweep_cascade_includes_descendants_through_the_port(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    child = ws / "child"
    child.mkdir()
    seed_pair(ws, lr, pair_id="sha256:root", summary="Root note about Jane Doe")
    seed_pair(child, lr, pair_id="sha256:child", summary="Child note about Jane Doe")
    host = ErasureHost(discover_descendants=chain_descendants)
    r_no = erasure.sweep(str(ws), "Jane Doe", cascade=False, log_root=lr, host=host)
    assert all("child" not in f for f in r_no.hits_by_folder)
    r_yes = erasure.sweep(str(ws), "Jane Doe", cascade=True, log_root=lr, host=host)
    assert any("child" in f for f in r_yes.hits_by_folder)
    assert "discover_descendants" not in r_yes.blind_spots


def test_sweep_cascade_without_descendants_port_names_the_blind_spot(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    child = ws / "child"
    child.mkdir()
    seed_pair(ws, lr, pair_id="sha256:root", summary="Root note about Jane Doe")
    seed_pair(child, lr, pair_id="sha256:child", summary="Child note about Jane Doe")
    report = erasure.sweep(str(ws), "Jane Doe", cascade=True, log_root=lr)
    assert report.blind_spots["discover_descendants"] == [str(ws.resolve())]
    assert {h.pair_id for h in report.hits_by_kind["pair"]} == {"sha256:root"}


def test_dry_run_makes_no_writes(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:dryrun", summary="About Jane Doe")
    log = MutationLog(ws, log_root=lr)
    before = list(log.replay())
    report = _execute(isolated_env, dry_run=True)
    assert report.dry_run is True
    assert report.composite_tombstone_id == ""
    assert report.purged_event_count == 0
    assert report.erasure_mode == ""
    assert report.controller_countersigned is False
    assert report.verdict == "auto"
    assert len(list(log.replay())) == len(before)
    assert forgotten_subjects.list_subjects(ws) == []


def test_execute_writes_composite_tombstone(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:e1", summary="Re: Jane Doe agreement")
    seed_pair(ws, lr, pair_id="sha256:e2", summary="Followup on Jane Doe")
    report = _execute(isolated_env, legal_basis="art_17_1_b", requester_ref="req:42",
                      reason="consent withdrawn")
    assert report.composite_tombstone_id.startswith("erase-composite:")
    assert report.erasure_mode == "two-key"
    assert report.controller_countersigned is True and report.verdict == "auto"
    composites = [e for e in MutationLog(ws, log_root=lr).replay()
                  if e.event == "system" and (e.extra or {}).get("kind") == "erasure_composite"]
    assert len(composites) == 1
    c = composites[0].extra
    assert c["legal_basis"] == "art_17_1_b" and c["requester_ref"] == "req:42"
    assert "Jane Doe" not in json.dumps(c)
    assert c["subject_preview"] == "[REDACTED]"
    assert c["affected_pair_count"] == 2
    assert "erase_versum_mirror" in c["blind_spots"]


def test_leaky_reason_is_scrubbed_from_all_permanent_records(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:p1", summary="Re: Jane Doe")
    req = erasure.request(str(ws), "Jane Doe", requester_ref="req:leak",
                          reason="Jane Doe asked us to forget her", log_root=lr)
    _execute(isolated_env, requester_ref="req:leak", reason="erase Jane Doe per DSAR",
             request_id=req["request_id"])
    log = MutationLog(ws, log_root=lr)
    assert "jane doe" not in log.log_file.read_text(encoding="utf-8").lower()
    composites = [e for e in log.replay() if (e.extra or {}).get("kind") == "erasure_composite"]
    assert composites[0].extra["reason"] == "erase [REDACTED] per DSAR"


def test_execute_writes_individual_purges_named_by_opaque_ref(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:p1", summary="Re: Jane Doe A")
    seed_pair(ws, lr, pair_id="sha256:p2", summary="Re: Jane Doe B")
    _execute(isolated_env)
    log = MutationLog(ws, log_root=lr)
    refs = {e.pair_id for e in log.replay() if e.event == "purge"}
    assert forgotten_subjects.purged_pair_ref(log.folder_path, "sha256:p1") in refs
    assert forgotten_subjects.purged_pair_ref(log.folder_path, "sha256:p2") in refs
    assert "sha256:p1" not in refs and "sha256:p2" not in refs
    assert MutationLog(ws, log_root=lr).verify_chain().ok


def test_execute_refuses_without_or_with_unknown_legal_basis(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:x", summary="Jane Doe")
    with pytest.raises(ValueError, match="legal_basis"):
        _execute(isolated_env, legal_basis="")
    with pytest.raises(ValueError, match="unknown legal_basis"):
        _execute(isolated_env, legal_basis="art_99")
    with pytest.raises(ValueError, match="requester_ref"):
        _execute(isolated_env, requester_ref="")
    with pytest.raises(ValueError, match="reason"):
        _execute(isolated_env, reason="")
    with pytest.raises(ValueError, match="subject"):
        _execute(isolated_env, subject="   ")
    assert erasure.VALID_LEGAL_BASES is VALID_LEGAL_BASES is mutation_log.VALID_LEGAL_BASES


def test_execute_single_key_without_controller(tmp_path):
    signing.ensure_keypair()
    assert signing.public_controller_key_fingerprint() is None
    ws, lr = tmp_path / "ws", tmp_path / "logs"
    ws.mkdir()
    seed_pair(ws, lr, pair_id="sha256:x", summary="About Jane Doe")
    report = erasure.execute(str(ws), "Jane Doe", legal_basis="art_17_1_a",
                             requester_ref="r", reason="t", log_root=lr)
    assert report.purged_event_count >= 1
    assert report.erasure_mode == "single-key"
    assert report.controller_countersigned is False
    # the purge released, so the verdict is the releasing word, not `refused`
    assert report.verdict == "auto"
    assert report.to_dict()["verdict"] == "auto"
    assert signing.public_controller_key_fingerprint() is None
    tomb = [e for e in MutationLog(ws, log_root=lr).replay() if e.event == "purge"]
    assert tomb and tomb[0].extra.get("erasure_mode") == "single-key"


def test_require_controller_refuses_before_any_write(tmp_path):
    signing.ensure_keypair()
    ws, lr = tmp_path / "ws", tmp_path / "logs"
    ws.mkdir()
    seed_pair(ws, lr, pair_id="sha256:x", summary="About Jane Doe")
    before = list(MutationLog(ws, log_root=lr).replay())
    with pytest.raises(erasure.ControllerKeyMissingError) as exc:
        erasure.execute(str(ws), "Jane Doe", legal_basis="art_17_1_a", requester_ref="r",
                        reason="t", log_root=lr, require_controller=True)
    assert exc.value.verdict == "refused"
    assert [e.audit_id for e in MutationLog(ws, log_root=lr).replay()] == [e.audit_id for e in before]
    assert forgotten_subjects.list_subjects(ws) == []


def test_verdict_words_come_from_the_governance_alphabet():
    from loomground_governance import vocabulary
    alphabet = set(vocabulary("verdicts")["alphabet"])
    assert erasure.verdict_for("request") == "human"
    assert erasure.verdict_for("sweep") == erasure.verdict_for("dry_run") == "auto"
    assert erasure.verdict_for("execute", controller_present=True) == "auto"
    assert erasure.verdict_for("execute", controller_present=False) == "auto"
    assert erasure.verdict_for("execute", controller_present=True,
                               require_controller=True) == "auto"
    assert erasure.verdict_for("execute", controller_present=False,
                               require_controller=True) == "refused"
    assert erasure.verdict_for("something-else") == "human"
    for state in erasure.STATES:
        assert erasure.verdict_for(state, controller_present=True) in alphabet


def test_only_a_non_releasing_verdict_accompanies_a_purge_that_released():
    """The verdict word means what the governance vocabulary says it means:
    a report whose purge released never carries a non-releasing word."""
    from loomground_governance import vocabulary
    releases = vocabulary("verdicts")["releases_at_master"]
    for present in (True, False):
        assert releases[erasure.verdict_for("execute", controller_present=present)] is True
    assert releases[erasure.verdict_for("execute", controller_present=False,
                                        require_controller=True)] is False


def test_forgotten_subject_blocks_reingest_via_check(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:f1", summary="Re: Jane Doe")
    report = _execute(isolated_env)
    hits = forgotten_subjects.check(str(ws), "Jane Doe")
    assert hits == [report.forgotten_subject_hash]
    assert forgotten_subjects.check(str(ws), "") == []
    assert forgotten_subjects.check(str(ws), "John Smith") == []
    assert forgotten_subjects.check_text(str(ws), "Jane Doe") == hits
    assert erasure.EraseGuardHit is forgotten_subjects.EraseGuardHit


def test_erase_request_writes_erasure_requested_event(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    res = erasure.request(str(ws), "Jane Doe", requester_ref="req:intake",
                          reason="DSAR ticket #42", log_root=lr)
    assert res["request_id"].startswith("erase-req:")
    assert res["audit_id"] and res["folder"] == str(ws.resolve())
    intake = [e for e in MutationLog(ws, log_root=lr).replay()
              if e.event == "system" and (e.extra or {}).get("kind") == "ERASURE_REQUESTED"]
    assert len(intake) == 1
    e = intake[0]
    assert e.extra["request_id"] == res["request_id"]
    assert e.extra["requester_ref"] == "req:intake"
    assert e.extra["subject_preview"] == "[REDACTED]"
    assert "Jane Doe" not in json.dumps(e.extra)
    with pytest.raises(ValueError):
        erasure.request(str(ws), "Jane Doe", requester_ref="", reason="x", log_root=lr)


def test_erase_status_returns_cascade_manifest(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:s1", summary="Re: Jane Doe target")
    req = erasure.request(str(ws), "Jane Doe", requester_ref="req:full", reason="DSAR", log_root=lr)
    rid = req["request_id"]
    _execute(isolated_env, legal_basis="art_17_1_b", requester_ref="req:full",
             reason="DSAR", request_id=rid)
    manifest = erasure.status(str(ws), rid, log_root=lr)
    assert manifest["request_id"] == rid
    assert manifest["requested"] is not None and manifest["executed"] is not None
    assert manifest["executed"]["purged_pair_count"] >= 1
    assert len(manifest["purges"]) >= 1
    assert manifest["forgotten"]["subject_hash"]


def test_erasure_leaves_no_subject_on_chain_even_for_legacy_pair_ids(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    log = MutationLog(ws, log_root=lr)
    log.append(LogEvent(event="ingest", folder_path=str(ws), pair_id="card:Anna Schmidt",
                        channel="fact", actor="user",
                        extra={"kind": "fact-intake", "subject_id": "Anna Schmidt"}))
    seed_pair(ws, lr, pair_id="sha256:note", summary="Anna Schmidt owes 5 EUR")
    req = erasure.request(str(ws), "Anna Schmidt", requester_ref="req:rt", reason="DSAR", log_root=lr)
    report = _execute(isolated_env, subject="Anna Schmidt", requester_ref="req:rt",
                      reason="DSAR", request_id=req["request_id"])
    assert report.purged_event_count >= 2
    chain_text = MutationLog(ws, log_root=lr).log_file.read_text(encoding="utf-8").lower()
    assert "anna" not in chain_text and "schmidt" not in chain_text
    manifest = erasure.status(str(ws), req["request_id"], log_root=lr)
    assert len(manifest["purges"]) == 2
    assert {p["pair_id"] for p in manifest["purges"]} == {
        forgotten_subjects.purged_pair_ref(log.folder_path, "card:Anna Schmidt"),
        forgotten_subjects.purged_pair_ref(log.folder_path, "sha256:note"),
    }


def test_status_stitches_legacy_raw_id_chains(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    rid = "erase-req:legacy0001"
    log = MutationLog(ws, log_root=lr)
    log.append(LogEvent(event="system", folder_path=str(ws),
                        pair_id=f"erasure-track:{rid}:sha256:old", channel="system",
                        actor="erasure:user",
                        extra={"kind": "erasure_pair_purge_start", "request_id": rid,
                               "erasure_request_id": rid, "purged_pair_id": "sha256:old",
                               "subject_preview": "[REDACTED]"}))
    log.append_raw(event="purge", pair_id="sha256:old", lifecycle_state="purged",
                   channel="system", actor="system:purge",
                   extra={"kind": "purge_tombstone", "purged_event_count": 1,
                          "legal_basis": "art_17_1_a"})
    manifest = erasure.status(str(ws), rid, log_root=lr)
    assert len(manifest["purges"]) == 1
    assert manifest["purges"][0]["pair_id"] == "sha256:old"


def test_erasure_guard_failure_has_no_destructive_side_effects(tmp_path, monkeypatch):
    signing.ensure_keypair()
    ws, lr = tmp_path / "workspace", tmp_path / "logs"
    ws.mkdir()
    log = MutationLog(ws, log_root=lr)
    log.append(LogEvent(event="ingest", folder_path=str(ws), pair_id="pair:guarded",
                        lifecycle_state="live", channel="document", actor="test",
                        extra={"pair": {"problem": {"summary": "acmecorp record"},
                                        "solution": {"body": "acmecorp record"}}}))
    before = [e.audit_id for e in log.replay()]

    def _fail_ensure(*args, **kwargs):
        raise OSError("read-only ledger")

    monkeypatch.setattr(forgotten_subjects, "ensure", _fail_ensure)
    with pytest.raises(erasure.ErasureGuardRegistrationError, match="erasure not started"):
        erasure.execute(str(ws), "acmecorp", legal_basis="art_17_1_a",
                        requester_ref="requester:opaque", reason="retention ended", log_root=lr)
    after = list(log.replay())
    assert [e.audit_id for e in after] == before
    assert all(e.event != "purge" for e in after)


def test_absent_versum_port_is_a_named_blind_spot_and_purges_still_run(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:v1", summary="Jane Doe file")
    report = _execute(isolated_env, host=ErasureHost(discover_descendants=chain_descendants))
    assert report.purged_event_count == 1
    assert report.blind_spots["erase_versum_mirror"] == [str(ws.resolve())]
    assert report.cascade_manifest[str(ws.resolve())]["versum_blind_spot"] is True
    assert report.versum_sealed == []
    assert set(report.blind_spots) >= {"scan_drafts", "scan_cards", "redact_drafts", "redact_cards"}


def test_absent_scan_ports_are_named_per_folder_and_the_sweep_completes(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    child = ws / "child"
    child.mkdir()
    seed_pair(ws, lr, pair_id="sha256:r", summary="Jane Doe root")
    seed_pair(child, lr, pair_id="sha256:c", summary="Jane Doe child")
    report = erasure.sweep(str(ws), "Jane Doe", cascade=True, log_root=lr,
                           host=ErasureHost(discover_descendants=chain_descendants))
    folders = sorted([str(ws.resolve()), str(child.resolve())])
    assert sorted(report.blind_spots["scan_cards"]) == folders
    assert sorted(report.blind_spots["scan_drafts"]) == folders
    assert report.blind_spots["pair_from_event"] == ["*"]
    assert report.blind_spots["replace_ci"] == ["*"]
    assert {h.pair_id for h in report.hits_by_kind["pair"]} == {"sha256:r", "sha256:c"}
    assert report.hits_by_kind["card"] == [] and report.hits_by_kind["draft"] == []
    assert report.to_dict()["blind_spots"]["scan_cards"] == report.blind_spots["scan_cards"]


def test_bound_ports_are_called_and_leave_no_blind_spot(isolated_env, full_host):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:b1", summary="Jane Doe file")
    seed_pair(ws, lr, pair_id="sha256:b2", summary="other file")
    full_host.fakes["drafts"].put(ws, "memo", "Jane Doe called twice; Jane Doe again")
    full_host.fakes["cards"].put(ws, "card:Jane Doe", "{}")
    full_host.fakes["cards"].put(ws, "card:other", "note on Jane Doe")
    preview = erasure.sweep(str(ws), "Jane Doe", log_root=lr, host=full_host)
    assert preview.blind_spots == {}
    assert [h.snippet for h in preview.hits_by_kind["draft"]] == ["memo: 2 occurrence(s)"]
    assert {h.pair_id for h in preview.hits_by_kind["card"]} == {
        "card-file:card:other", "card-file:card:[REDACTED]"}
    report = _execute(isolated_env, host=full_host)
    assert report.blind_spots == {}
    assert report.purged_event_count == 1
    versum_calls = full_host.fakes["versum"].calls
    assert versum_calls == [(str(ws.resolve()), {"sha256:b1"}, {
        "physical": True, "reason": f"[erase-req:{report.request_id}] t", "actor": "user"})]
    assert report.draft_surfaces_redacted == 1 and report.card_files_redacted == 1
    assert report.card_files_deleted == 1
    manifest = report.cascade_manifest[str(ws.resolve())]
    assert manifest["cards"]["deleted"] == ["card:[REDACTED]"]
    assert full_host.fakes["drafts"].files[str(ws.resolve())]["memo"] == \
        "[REDACTED] called twice; [REDACTED] again"


def test_replayed_execute_is_a_noop_without_a_second_composite(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:r1", summary="Jane Doe file")
    first = _execute(isolated_env)
    second = _execute(isolated_env)
    assert first.replayed_noop is False and second.replayed_noop is True
    assert second.composite_tombstone_id == ""
    assert second.forgotten_subject_hash == first.forgotten_subject_hash
    composites = [e for e in MutationLog(ws, log_root=lr).replay()
                  if (e.extra or {}).get("kind") == "erasure_composite"]
    assert len(composites) == 1
    assert len(forgotten_subjects.list_subjects(ws)) == 1


def test_sealed_folder_is_named_versum_sealed_on_dry_run(isolated_env):
    ws, lr = isolated_env["workspace"], isolated_env["log_root"]
    seed_pair(ws, lr, pair_id="sha256:s", summary="Jane Doe file")
    seal.seal_folder(ws, passphrase="pw", log_root=lr)
    report = _execute(isolated_env, dry_run=True)
    assert report.versum_sealed == [str(ws.resolve())]
    assert report.sweep.versum_sealed == [str(ws.resolve())]
    assert report.purged_event_count == 0
    assert seal.is_sealed(ws, log_root=lr)


def test_end_to_end_request_sweep_execute_status_with_generated_keys(tmp_path, full_host):
    """Fresh operator + controller keys on a temp folder; every stage of the
    protocol; the chain verifies afterwards and the subject is off it."""
    signing.ensure_keypair()
    signing.ensure_controller_keypair()
    assert signing.public_controller_key_fingerprint() is not None
    ws, lr = tmp_path / "ws", tmp_path / "logs"
    ws.mkdir()
    seed_pair(ws, lr, pair_id="sha256:e2e-1", summary="Contract with Jane Doe",
              body="Jane Doe signed on 2025-01-01.")
    seed_pair(ws, lr, pair_id="sha256:e2e-2", summary="Q3 revenue", body="unrelated")
    req = erasure.request(str(ws), "Jane Doe", requester_ref="dsar:7", reason="Art. 17(1)(b)",
                          log_root=lr, host=full_host)
    preview = erasure.sweep(str(ws), "Jane Doe", log_root=lr, host=full_host)
    assert preview.total_hits() == 1 and preview.blind_spots == {}
    report = erasure.execute(str(ws), "Jane Doe", legal_basis="art_17_1_b",
                             requester_ref="dsar:7", reason="Art. 17(1)(b)", log_root=lr,
                             request_id=req["request_id"], host=full_host, require_controller=True)
    assert report.erasure_mode == "two-key" and report.verdict == "auto"
    assert report.purged_pairs == ["sha256:e2e-1"] and report.purged_event_count == 1
    manifest = erasure.status(str(ws), req["request_id"], log_root=lr)
    assert manifest["requested"] and manifest["executed"] and manifest["forgotten"]
    assert [p["legal_basis"] for p in manifest["purges"]] == ["art_17_1_b"]
    log = MutationLog(ws, log_root=lr)
    assert log.verify_chain().ok
    assert "jane doe" not in log.log_file.read_text(encoding="utf-8").lower()
    assert {e.pair_id for e in log.replay()} >= {"sha256:e2e-2"}
    tomb = [e for e in log.replay() if e.event == "purge"][0]
    assert tomb.extra.get("erasure_mode") == "two-key"
    assert forgotten_subjects.check(ws, "Jane Doe") == [report.forgotten_subject_hash]
