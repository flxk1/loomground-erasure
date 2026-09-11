<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Seam: RVND → loomground-erasure

Source: `flxk1/RVND` at commit `bac579b`, `server/src/rvnd/`: `erasure.py`, `pending_erase.py`, `forgotten_subjects.py`. The protocol layer moved; the host stores stayed and are reached through one ports object.

## Module map

| RVND module (bac579b) | Package module | What moved |
|---|---|---|
| `rvnd/forgotten_subjects.py` | `loomground_erasure.forgotten_subjects` | whole: salted ledger, `ensure`/`add`/`contains`/`check`, `opaque_ref`, `purged_pair_ref`, durability (owner-only atomic writes, OS lock, fail-closed strict reader) |
| `rvnd/pending_erase.py` | `loomground_erasure.pending_erase` | whole: `arm_marker`, `discover_sealed_in_scope`, `verify_markers_for_unseal`, `apply_markers`, `feature_enabled`, `PENDING_ERASE_ENV`; over `loomground_lock.seal`, `loomground_audit_chain.signing`, `mutation_log._file_lock` |
| `rvnd/erasure.py` | `loomground_erasure.erasure` | protocol layer: `SweepHit`, `SweepReport`, `ExecutionReport`, `ErasureGuardRegistrationError`, `request` / `sweep` (`dry_run`) / `status` / `execute`, `_validate_subject`, `_validate_legal_basis`, `_short`, `_redacted_snippet`, `_event_text_haystack`, `_classify_kind`, `_logs_for_sweep`, composite tombstone, forgotten-subjects write, `_write_forgotten_breadcrumb` |
| — | `loomground_erasure.ports` | new: `ErasureHost`, `BLIND_SPOT_MEANING`, `default_pair_from_event`, `scrub_literal` |

Added on extraction: `erasure.verdict_for(state, controller_present=)` and `erasure.STATES` (the three states in the `.lg` verdict alphabet), `execute(require_controller=)` and `ControllerKeyMissingError`, `ExecutionReport.erasure_mode` / `.verdict` / `.blind_spots`, `SweepReport.blind_spots`, `forgotten_subjects.bind_chain_pair_refs`, `pending_erase.bind_seal_hooks`.

## Preserved names

From `seam-surface.json`: `erasure.{_event_text_haystack, sweep}`, `forgotten_subjects.purged_pair_ref` (`pending_erase` has no external importers). `erasure._erase_versum_mirror` is host-side and stays in RVND.

Every public def/class of the three source modules, plus the private names RVND's tests address as module attributes, is importable with the same positional/keyword shape (`folder`, `log_root=`, `legal_basis=`, `requester_ref=`, `reason=`, `actor=`, `request_id=`, `queue_if_sealed=`, `controller_signer=`) plus the `host=` ports parameter on `sweep`, `dry_run`, `request`, `execute` and `pending_erase.apply_markers` / `_select_matching_pairs`. `tests/test_surface.py` asserts the list.

## Ports: `ErasureHost` and the blind spot of each absent port

Every port is optional. An absent port is named in `SweepReport.blind_spots` / `ExecutionReport.blind_spots` (`{port: [folder, ...]}`, `"*"` = every folder) and on the composite tombstone (`extra.blind_spots`, the port names); `apply_markers` returns the same map. The sweep and the chain purge complete regardless; the report never claims an uninspected store clean.

| Port | Signature | Absent → |
|---|---|---|
| `pair_from_event` | `(event) -> dict \| None` | chain-native body (`event.extra["pair"]`) only; a body the host keeps outside the chain event is unseen |
| `discover_descendants` | `(folder, log_root=) -> [folder]` | with `cascade=True` the root alone is swept; blind spot names the root |
| `replace_ci` | `(text, needle) -> (text, count)` | the literal case-insensitive scrub (`ports.scrub_literal`) cleans reasons, snippets and deleted ids; a host scrub that also folds confusables is absent |
| `scan_drafts` | `(folder, subject, log_root=) -> {hits, unreadable, sealed}` | drafts uninspected, per folder |
| `redact_drafts` | `(folder, subject, log_root=) -> {ok, redacted, deleted}` | drafts untouched on `execute` / `apply_markers`, per folder |
| `scan_cards` | `(folder, subject, log_root=) -> {hits, identity, unreadable, sealed}` | cards uninspected, per folder |
| `redact_cards` | `(folder, subject, log_root=) -> {ok, redacted, deleted}` | cards untouched, per folder |
| `erase_versum_mirror` | `(folder, pair_ids, *, physical, reason, actor, log_root) -> (errors, sealed_folders)` | knowledge mirror of the purged pairs neither erased nor certified; per folder with purges, also `cascade_manifest[folder].versum_blind_spot` |

`versum_sealed` / `drafts_sealed` / `cards_sealed` keep RVND's meaning: the store is inside a seal blob (checked through `loomground_lock.seal.is_sealed` for the versum mirror; through the `sealed` flag of the scan ports for drafts and cards).

## Grounding and cross-plane binding

- `VALID_LEGAL_BASES` is imported from `loomground_audit_chain.mutation_log`; there is no second list.
- Verdicts: `verdict_for` reads `loomground_governance.vocabulary("verdicts")` at call time. `request` → `human`; `sweep` / `dry_run` / `status` → the one member with `releases_at_master` (`auto`); `execute` → `auto` when a controller key co-signs, `refused` when it is missing. `execute(require_controller=True)` enforces the `refused` case by raising `ControllerKeyMissingError` before any write; the default keeps RVND's L0-first behaviour (single-key purge, `erasure_mode: single-key` on the tombstone and report).
- Importing the package runs `forgotten_subjects.bind_chain_pair_refs()`: `loomground_audit_chain.mutation_log.purged_pair_ref` is pointed at the folder-salted ref, so the purge tombstone the chain writes and the tracker this package writes name a purged pair identically (`status` stitches by equality). RVND's adapter did the same binding.
- `pending_erase.bind_seal_hooks(host)` registers `pending_erase_verify` / `pending_erase_apply` on `loomground_lock.host_deps`; both are no-ops while `WORKSPACE_PENDING_ERASE` is unset.
- `pending_erase.discover_sealed_in_scope` reads `loomground_workspace.workspace_registry.list_known_workspaces` (the raw registry, unscoped). RVND's `adapters.workspace.list_known_workspaces` applies a per-principal scope by default; a host that needs the scoped read wraps `execute` accordingly.

## Behaviour changes on extraction

- `_redacted_snippet` replaces every occurrence of the subject (the source replaced the first only, so a subject twice within 80 characters survived into the preview).
- Reports gain `blind_spots`; the composite tombstone gains `extra.blind_spots` (port names, no folders).
- `apply_markers` reports `blind_spots` and takes `host=`; the host-side draft/card parity moves behind `redact_drafts` / `redact_cards`.

## Compatibility constants

| Name | Value |
|---|---|
| `pending_erase.PENDING_ERASE_ENV` | `"WORKSPACE_PENDING_ERASE"` |
| `forgotten_subjects.FORGOTTEN_DIR_NAME` | `"forgotten_subjects"` |
| `pending_erase._MARKER_SUFFIX` | `".pending-erase.jsonl"` |
| `ports.REDACTED` | `"[REDACTED]"` |

Host-agnostic: `grep -rniE 'rvnd|claude|anthropic|mcp|CLAUDE_CODE' src/ tests/` is empty (`tests/test_surface.py` reads the pattern from this line); `grep -rn 'card_store\|draft_store\|from .memory\|redaction\|adapters' src/` is empty.

## Stays in RVND, and why

| Module / function | Reason |
|---|---|
| `rvnd/card_store.py`, `rvnd/draft_store.py` | host file stores; reached through `scan_cards` / `redact_cards` / `scan_drafts` / `redact_drafts` |
| `rvnd/memory.py` (`_pair_from_event`, `discover_descendants`, `discover_folders`) | host memory model and folder walk; `pair_from_event`, `discover_descendants` ports |
| `rvnd/redaction.py` (`replace_ci`) | host scrub with confusable folding; `replace_ci` port |
| `rvnd/adapters/versum.py`, `rvnd/erasure._erase_versum_mirror` | host knowledge sink; `erase_versum_mirror` port (RVND keeps the function and passes it) |
| `rvnd/adapters/workspace.py` | per-principal registry scope, a host access policy |
| `rvnd/lock` decisions scrub | `execute` reaches `loomground_lock.decisions.DecisionsStore.erase_subject` directly (the lock is a sibling package now) |
| host-store tests `test_erasure_cards.py`, `test_erasure_drafts.py`, `test_erasure_sealed_versum.py`, `test_erasure_versum_purge.py` | exercise the stores; run in RVND through the shim |

## How RVND shims

`rvnd/adapters/erasure.py` builds the ports object and binds the seal hooks:

```python
from loomground_erasure import ErasureHost, bind_seal_hooks
from .. import card_store, draft_store
from ..memory import _pair_from_event, discover_descendants
from ..redaction import replace_ci
from ..erasure import _erase_versum_mirror          # stays host-side

def _pair(evt):
    from .versum import read_disk_versum_records    # post body-drop bodies
    return _pair_from_event(evt) or _versum_body(evt.folder_path, evt.pair_id)

HOST = ErasureHost(
    pair_from_event=_pair, discover_descendants=discover_descendants, replace_ci=replace_ci,
    scan_drafts=draft_store.scan, redact_drafts=draft_store.redact,
    scan_cards=card_store.scan, redact_cards=card_store.redact,
    erase_versum_mirror=_erase_versum_mirror,
)
bind_seal_hooks(HOST)
```

- `rvnd/erasure.py`: keeps `_erase_versum_mirror`; re-exports `sweep`, `dry_run`, `request`, `status`, `execute`, `_event_text_haystack`, the report classes, `EraseGuardHit`, `ErasureGuardRegistrationError` from `loomground_erasure.erasure`, with `functools.partial(..., host=HOST)` on `sweep` / `dry_run` / `request` / `execute`.
- `rvnd/pending_erase.py`, `rvnd/forgotten_subjects.py`: import-only shims (`from loomground_erasure.pending_erase import *` plus the private names the tests address; `sys.modules` aliasing keeps monkeypatching of `forgotten_subjects.ensure` effective).
- `rvnd/adapters/audit_chain.py` may drop its own `purged_pair_ref` rebinding; the package's import-time binding is identical.
