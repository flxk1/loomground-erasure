<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Host seam

`loomground-erasure` owns the erasure protocol, pending markers, and
forgotten-subject ledger. Host stores are reached through one optional
`ErasureHost` object; the package imports no host implementation.

## Public modules

| Module | Responsibility |
|---|---|
| `erasure` | `request`, `sweep`, `dry_run`, `status`, `execute`; reports, verdicts, composite tombstone |
| `pending_erase` | markers for sealed stores and seal-hook binding |
| `forgotten_subjects` | salted subject ledger and stable purged-pair references |
| `ports` | `ErasureHost`, blind-spot meanings, default event reader, literal scrubber |

`tests/test_surface.py` fixes the importable public names and call shapes.

## Ports and blind spots

Every port is optional. An absent port is recorded in
`SweepReport.blind_spots`, `ExecutionReport.blind_spots`, marker results, and
the composite tombstone. The chain purge may complete, but the report never
claims an uninspected store is clean.

| Port | Shape | If absent |
|---|---|---|
| `pair_from_event` | `(event) -> dict | None` | inspect only `event.extra["pair"]` |
| `discover_descendants` | `(folder, log_root=) -> [folder]` | cascade inspects only the root and names the gap |
| `replace_ci` | `(text, needle) -> (text, count)` | use literal case-insensitive scrubbing |
| `scan_drafts`, `scan_cards` | store scanners | corresponding store remains uninspected |
| `redact_drafts`, `redact_cards` | store redactors | corresponding store remains untouched |
| `erase_versum_mirror` | erase mirrored knowledge records | mirror remains uncertified and is named as a gap |

Scanner results may mark a store `sealed`; this means the data lives inside a
seal blob and cannot be inspected until unsealed.

## Cross-plane bindings

- Legal bases come from
  `loomground_audit_chain.mutation_log.VALID_LEGAL_BASES`.
- `verdict_for` reads the Loomground verdict vocabulary at call time:
  `request` is human-reviewed, `sweep`/`dry_run`/`status` are read-only, and a
  successful `execute` records whether it used one or two keys. Requiring a
  missing controller key raises `ControllerKeyMissingError` before any write.
- Import binds the audit chain's `purged_pair_ref` to the folder-salted
  forgotten-subject reference so the chain tombstone and ledger agree.
- `pending_erase.bind_seal_hooks(host)` registers verify/apply hooks with
  `loomground-lock`; both remain inactive unless `WORKSPACE_PENDING_ERASE=1`.
- Sealed-scope discovery reads the raw known-workspace registry. A host needing
  principal-scoped discovery must wrap the operation with its access policy.

## Adapter sketch

```python
from loomground_erasure import ErasureHost, bind_seal_hooks, execute

host = ErasureHost(
    pair_from_event=pair_from_event,
    discover_descendants=discover_descendants,
    replace_ci=replace_ci,
    scan_drafts=drafts.scan,
    redact_drafts=drafts.redact,
    scan_cards=cards.scan,
    redact_cards=cards.redact,
    erase_versum_mirror=erase_mirror,
)
bind_seal_hooks(host)
report = execute(folder, subject, legal_basis="art_17_1_b", host=host)
```

The host owns its card, draft, memory, redaction, mirrored-knowledge, and
principal-scope implementations. They consume this port contract and remain
outside the package dependency graph.
