# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Surface, grounding and containment: every name the host seam survey lists
for the three moved modules, every public def/class of the source modules at
the extraction commit, host-compatible signatures plus the ports parameter,
the legal-basis alphabet from the chain, the verdict words from governance,
and no host store or host name under ``src/``."""
from __future__ import annotations

import inspect
import pathlib
import re
import subprocess

import pytest

import loomground_erasure
from loomground_audit_chain import mutation_log
from loomground_erasure import erasure, forgotten_subjects, pending_erase, ports

REPO = pathlib.Path(__file__).resolve().parents[1]

# seam-surface.json names for the three modules (the host keeps _erase_versum_mirror).
SEAM_SURFACE = {
    "erasure": ["_event_text_haystack", "sweep"],
    "pending_erase": [],
    "forgotten_subjects": ["purged_pair_ref"],
}

# Every public def / class of the source modules at the extraction commit.
SOURCE_PUBLIC = {
    "erasure": ["SweepHit", "SweepReport", "ErasureGuardRegistrationError", "ExecutionReport",
                "sweep", "dry_run", "request", "status", "execute", "EraseGuardHit"],
    "pending_erase": ["PENDING_ERASE_ENV", "PendingEraseError", "feature_enabled", "arm_marker",
                      "discover_sealed_in_scope", "verify_markers_for_unseal", "apply_markers"],
    "forgotten_subjects": ["FORGOTTEN_DIR_NAME", "EraseGuardHit", "salt_for", "opaque_ref",
                           "purged_pair_ref", "ensure", "add", "contains", "list_subjects",
                           "check", "check_text"],
}

# Private names the host's tests address as module attributes.
SOURCE_PRIVATE = {
    "erasure": ["_validate_subject", "_validate_legal_basis", "_short", "_redacted_snippet",
                "_event_text_haystack", "_classify_kind", "_logs_for_sweep",
                "_write_forgotten_breadcrumb"],
    "pending_erase": ["_marker_ledger_path", "_canonical_bytes", "_body_of", "_read_markers",
                      "_write_markers", "_select_matching_pairs", "_canonical_subject_tokens"],
    "forgotten_subjects": ["_folder_dir", "_salt_path", "_ledger_path", "_hash_subject",
                           "_atomic_write_private", "_candidate_strings", "_TOKEN_RE"],
}

MODULES = {"erasure": erasure, "pending_erase": pending_erase, "forgotten_subjects": forgotten_subjects}


@pytest.mark.parametrize("module,names", [
    *[(m, n) for m, n in SEAM_SURFACE.items()],
    *[(m, n) for m, n in SOURCE_PUBLIC.items()],
    *[(m, n) for m, n in SOURCE_PRIVATE.items()],
])
def test_every_surface_name_is_importable(module, names):
    mod = MODULES[module]
    for name in names:
        assert hasattr(mod, name), f"{module}.{name}"
    for name in SOURCE_PUBLIC[module]:
        assert name in mod.__all__ or name.isupper() or name == "EraseGuardHit"


def test_host_side_versum_erase_stays_out():
    assert not hasattr(erasure, "_erase_versum_mirror")


def _params(fn):
    return inspect.signature(fn).parameters


def test_host_compatible_signatures_plus_ports():
    p = _params(erasure.execute)
    assert list(p)[:2] == ["folder_context", "subject"]
    for kw in ("legal_basis", "requester_ref", "reason", "controller_signer", "cascade",
               "dry_run", "log_root", "actor", "request_id", "queue_if_sealed", "host",
               "require_controller"):
        assert p[kw].kind is inspect.Parameter.KEYWORD_ONLY, kw
    assert p["host"].default is None and p["require_controller"].default is False
    v = _params(erasure.verdict_for)
    assert list(v) == ["state", "controller_present", "require_controller"]
    assert v["require_controller"].default is False
    for fn in (erasure.sweep, erasure.dry_run):
        q = _params(fn)
        assert list(q) == ["folder_context", "subject", "cascade", "log_root", "host"]
    q = _params(erasure.request)
    assert list(q) == ["folder_context", "subject", "requester_ref", "reason", "log_root", "actor", "host"]
    assert list(_params(erasure.status)) == ["folder_context", "request_id", "log_root"]
    assert list(_params(pending_erase.arm_marker)) == [
        "folder", "subject_norm", "request_id", "legal_basis", "requester_ref", "reason_safe", "log_root"]
    assert list(_params(pending_erase.verify_markers_for_unseal)) == [
        "folder", "log_dir", "sealed_path", "log_root"]
    assert list(_params(pending_erase.apply_markers)) == ["folder", "markers", "log_root", "actor", "host"]
    assert list(_params(pending_erase.discover_sealed_in_scope)) == ["folder_context", "cascade", "log_root"]
    assert list(_params(forgotten_subjects.ensure)) == ["folder", "subject", "request_id"]
    assert list(_params(forgotten_subjects.purged_pair_ref)) == ["folder", "pair_id"]
    assert list(_params(forgotten_subjects.opaque_ref)) == ["folder", "text", "domain"]
    assert list(_params(forgotten_subjects.check)) == ["folder", "text"]


def test_ports_object_names_every_store_and_its_blind_spot_meaning():
    host = ports.ErasureHost()
    assert host.absent() == ["pair_from_event", "discover_descendants", "replace_ci", "scan_drafts",
                             "redact_drafts", "scan_cards", "redact_cards", "erase_versum_mirror"]
    assert set(ports.BLIND_SPOT_MEANING) == set(host.absent())
    assert loomground_erasure.ErasureHost is ports.ErasureHost


def test_legal_bases_are_the_chains_single_list():
    assert erasure.VALID_LEGAL_BASES is mutation_log.VALID_LEGAL_BASES
    src = (REPO / "src" / "loomground_erasure" / "erasure.py").read_text()
    assert "VALID_LEGAL_BASES = " not in src
    assert re.search(r"art_17_1_[a-f]", src) is None


def test_readme_interface_uses_only_alphabet_words_for_the_state_mapping():
    from loomground_governance import vocabulary
    alphabet = set(vocabulary("verdicts")["alphabet"])
    text = (REPO / "README.md").read_text()
    interface = text.split("## Interface", 1)[1].split("## Family", 1)[0]
    mapping = re.findall(r"`(request|sweep|execute)`[^\n]*?→ `([a-z-]+)`", interface)
    assert {s for s, _ in mapping} >= {"request", "execute"}
    for state, word in mapping:
        assert word in alphabet, (state, word)
    for word in ("human", "refused"):
        assert f"`{word}`" in interface
    assert re.search(r"\b(allow|deny|approved|rejected|GO|NO-GO)\b", interface) is None


def _seam_grep_patterns() -> list[str]:
    """The two containment greps as ``docs/seam.md`` states them."""
    seam = (REPO / "docs" / "seam.md").read_text()
    line = next(l for l in seam.splitlines() if l.startswith("Host-agnostic:"))
    return [m.replace("\\|", "|") for m in re.findall(r"grep -rn\w* '([^']+)'", line)]


def test_src_and_tests_name_no_host_and_no_host_store():
    host_words, store_words = _seam_grep_patterns()
    src, tests = REPO / "src", REPO / "tests"
    for root in (src, tests):
        for path in root.rglob("*.py"):
            text = path.read_text()
            hits = [m.group(0) for m in re.finditer("(?i)" + host_words, text)]
            assert hits == [], (path, hits)
    for path in src.rglob("*.py"):
        assert re.search(store_words, path.read_text()) is None, path


def test_test_home_is_redirected_away_from_the_real_workspace():
    import os
    from loomground_audit_chain import signing
    home = pathlib.Path(os.environ["HOME"])
    assert str(pathlib.Path.home()) == str(home)
    assert str(mutation_log.resolve_log_root()).startswith(str(home))
    assert str(signing._key_root_dir()).startswith(os.environ["WORKSPACE_KEY_DIR"])
    assert not (home / ".workspace" / "keys").exists() or str(home).startswith(os.environ["TMPDIR"])


def test_git_tree_has_no_remote_and_flxk1_identity():
    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    remotes = subprocess.run(["git", "-C", str(REPO), "remote"], capture_output=True, text=True).stdout
    assert remotes.strip() == ""
    name = subprocess.run(["git", "-C", str(REPO), "config", "user.name"], capture_output=True, text=True).stdout
    assert name.strip() == "flxk1"
