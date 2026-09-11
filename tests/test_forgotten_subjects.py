# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Durability, fail-closed and match semantics of the forgotten-subject ledger."""
from __future__ import annotations

import json
import os

import pytest

from loomground_audit_chain import mutation_log
from loomground_erasure import forgotten_subjects


def test_ensure_is_idempotent_and_owner_only(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first_hash, first_added = forgotten_subjects.ensure(workspace, "acmecorp", "erase-req:first")
    second_hash, second_added = forgotten_subjects.ensure(workspace, "acmecorp", "erase-req:second")
    assert first_added is True
    assert second_added is False
    assert second_hash == first_hash
    ledger = forgotten_subjects._ledger_path(workspace)
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1
    if os.name != "nt":
        assert ledger.stat().st_mode & 0o077 == 0
        assert forgotten_subjects._salt_path(workspace).stat().st_mode & 0o077 == 0


def test_ensure_recognises_historical_row_salt(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    forgotten_subjects._folder_dir(workspace).mkdir()
    canonical_salt, historical_salt = "1" * 64, "2" * 64
    forgotten_subjects._salt_path(workspace).write_text(canonical_salt + "\n", encoding="utf-8")
    subject_hash = forgotten_subjects._hash_subject(historical_salt, "acmecorp")
    forgotten_subjects._ledger_path(workspace).write_text(
        json.dumps({"subject_hash": subject_hash, "salt": historical_salt,
                    "added_at": 1.0, "request_id": "erase-req:historical"}) + "\n",
        encoding="utf-8")
    ensured_hash, added = forgotten_subjects.ensure(workspace, "acmecorp", "erase-req:retry")
    assert (ensured_hash, added) == (subject_hash, False)
    assert forgotten_subjects.contains(workspace, "acmecorp") is True
    assert forgotten_subjects.contains(workspace, "othercorp") is False


def test_corrupt_ledger_fails_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    forgotten_subjects._folder_dir(workspace).mkdir()
    forgotten_subjects._ledger_path(workspace).write_text("not-json\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="corrupt forgotten-subject ledger"):
        forgotten_subjects.ensure(workspace, "acmecorp", "erase-req:corrupt")
    with pytest.raises(RuntimeError, match="corrupt forgotten-subject ledger"):
        forgotten_subjects.check(workspace, "acmecorp")
    assert forgotten_subjects.list_subjects(workspace) == []


def test_invalid_salt_fails_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    forgotten_subjects._folder_dir(workspace).mkdir()
    forgotten_subjects._salt_path(workspace).write_text("short\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid forgotten-subject salt"):
        forgotten_subjects.salt_for(workspace)


def test_add_appends_duplicates_and_list_subjects_dedupes(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    h1 = forgotten_subjects.add(workspace, "Jane Doe", "r1")
    h2 = forgotten_subjects.add(workspace, "jane doe", "r2")
    assert h1 == h2
    assert len(forgotten_subjects._ledger_path(workspace).read_text().splitlines()) == 2
    listed = forgotten_subjects.list_subjects(workspace)
    assert [row["subject_hash"] for row in listed] == [h1]
    assert "salt" not in listed[0]
    with pytest.raises(ValueError):
        forgotten_subjects.add(workspace, "   ", "r3")


def test_check_matches_token_and_full_text_but_never_substring(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    h_word = forgotten_subjects.ensure(workspace, "acmecorp", "r1")[0]
    h_phrase = forgotten_subjects.ensure(workspace, "Jane Doe", "r2")[0]
    assert forgotten_subjects.check(workspace, "invoice from ACMECORP today") == [h_word]
    assert forgotten_subjects.check(workspace, "  jane   DOE ") == [h_phrase]
    assert forgotten_subjects.check(workspace, "contact Jane Doe soon") == []
    assert forgotten_subjects.check(workspace, "acmecorporation") == []
    assert forgotten_subjects.check(workspace, "") == []
    assert forgotten_subjects.check_text(workspace, "acmecorp") == [h_word]
    hit = forgotten_subjects.EraseGuardHit([h_word], str(workspace))
    assert hit.hashes == [h_word] and "Refusing to re-ingest" in str(hit)


def test_opaque_refs_are_domain_separated_and_salt_stable(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    a = forgotten_subjects.opaque_ref(workspace, "card:Anna", domain="card-ref")
    b = forgotten_subjects.opaque_ref(workspace, "card:Anna", domain="pair-ref")
    assert a != b and len(a) == 64
    ref = forgotten_subjects.purged_pair_ref(workspace, "card:Anna")
    assert ref == "pair-ref:" + b[:16]
    assert forgotten_subjects.purged_pair_ref(workspace, "card:Anna") == ref
    assert forgotten_subjects.salt_for(workspace) == forgotten_subjects.salt_for(workspace)
    assert "Anna" not in ref


def test_chain_purged_pair_ref_port_is_bound_to_the_salted_ref():
    assert mutation_log.purged_pair_ref is forgotten_subjects.purged_pair_ref
