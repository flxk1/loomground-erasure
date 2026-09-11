<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## 0.1.0

* Extracted from RVND at commit `bac579b` (`flxk1/RVND`, `server/src/rvnd/`): `erasure.py` (protocol layer), `pending_erase.py` (whole) and `forgotten_subjects.py` (whole) become `loomground_erasure.{erasure,pending_erase,forgotten_subjects}`. Tests ported from `server/tests/test_erasure_068.py`, `test_erasure_pair_refs.py`, `test_pending_erase.py`, `test_forgotten_subjects_durability.py`; the host-store suites (`test_erasure_cards.py`, `test_erasure_drafts.py`, `test_erasure_sealed_versum.py`, `test_erasure_versum_purge.py`) stay with RVND.
* Ports split (`docs/seam.md`): the host stores — `card_store`, `draft_store`, `memory._pair_from_event` / `discover_descendants`, `redaction.replace_ci`, `adapters.versum` and `_erase_versum_mirror` — stay in RVND and are injected through one `ports.ErasureHost` object. An absent port is a named blind spot on `SweepReport` / `ExecutionReport` / `apply_markers` and on the composite tombstone; the sweep and the chain purge complete.
* Consumes `loomground-audit-chain` (chain, signing, `VALID_LEGAL_BASES`, `_file_lock`, audit drops), `loomground-lock` (seal state, unseal hooks, decisions scrub), `loomground-governance` (verdict vocabulary read at call time; `erasure.verdict_for`) and `loomground-workspace` (registry walk for sealed descendants).
* Added: `execute(require_controller=)` with `ControllerKeyMissingError` (the `refused` verdict); `ExecutionReport.erasure_mode` / `.verdict`; `forgotten_subjects.bind_chain_pair_refs` (run at import); `pending_erase.bind_seal_hooks`. `_redacted_snippet` now scrubs every occurrence of the subject.
* Licence: the source files carry `AGPL-3.0-only`, copyright flxk1; this package relicenses them to Apache-2.0 (code) / CC-BY-4.0 (README) by the same copyright holder, following the loomground-workspace extraction precedent. Felix confirms the relicensing.
