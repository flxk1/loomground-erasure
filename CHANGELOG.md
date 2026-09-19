<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## [0.1.1](https://github.com/flxk1/loomground-erasure/compare/loomground-erasure-v0.1.0...loomground-erasure-v0.1.1) (2026-09-19)


### Dependencies

* admit loomground-lock 0.2 ([084fb51](https://github.com/flxk1/loomground-erasure/commit/084fb51da224f0f34aacacaea69f5aa1d38072dc))

## 0.1.0

* Published the erasure protocol, pending markers, and forgotten-subject ledger as `loomground_erasure.{erasure,pending_erase,forgotten_subjects}`.
* Host stores are injected through one `ports.ErasureHost` object. An absent port is a named blind spot on `SweepReport`, `ExecutionReport`, `apply_markers`, and the composite tombstone; the sweep and chain purge may still complete.
* Consumes `loomground-audit-chain` (chain, signing, `VALID_LEGAL_BASES`, `_file_lock`, audit drops), `loomground-lock` (seal state, unseal hooks, decisions scrub), `loomground-governance` (verdict vocabulary read at call time; `erasure.verdict_for`) and `loomground-workspace` (registry walk for sealed descendants).
* Added: `execute(require_controller=)` with `ControllerKeyMissingError` (the `refused` verdict); `ExecutionReport.erasure_mode` / `.verdict`; `forgotten_subjects.bind_chain_pair_refs` (run at import); `pending_erase.bind_seal_hooks`. `_redacted_snippet` now scrubs every occurrence of the subject.
* Licence: the source files carry `AGPL-3.0-only`, copyright flxk1; this package relicenses them to Apache-2.0 (code) / CC-BY-4.0 (README) by the same copyright holder, following the loomground-workspace extraction precedent. Felix confirms the relicensing.
