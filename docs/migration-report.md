# Migration Report

## Multiparty Transit Safety Extensions

The change is backward compatible. Existing `MultipartyTransitionPlan` callers
do not need to set owner IDs, terminal maps, or late-bound args.

New callers that need participant-specific change must provide owner IDs for
all RGB inputs and matching `change_vouts_by_owner` entries. If
`require_distinct_owner_change_vouts` is enabled, duplicate owner vouts are
rejected.

New callers that need repeated ABI return names to bind to different outputs
must declare terminal IDs with vouts and map each return occurrence explicitly.
Mappings that reference unknown terminals or returns that are not produced fail.

Late-bound args require `build_advanced_transition_on_psbt`, which requires a
cloneable PSBT so the API can probe the RGB commitment txid without mutating
stock state. The API only commits the final cloned PSBT back to the caller when
late-bound args converge to a stable commitment txid. Non-converging
self-referential txid plans fail closed.

## Multiparty Input Assignment Selection

### Violations

`src/multiparty.rs` currently validates
`MultipartyTransitionInput::expected_assignments`, but after validation it still
adds every assignment returned for the same RGB input seal to the transition
builder. This violates the requirement that callers can select the exact
assignment(s) on a seal to consume.

### Impact

Callers using a seal that carries multiple assignments cannot build a transition
that consumes only one of them. The unintended assignments also affect transition
input counts, change-state creation, and script parameters derived from selected
input amounts.

### Migration Plan

1. Preserve legacy behavior when `expected_assignments` is empty by consuming all
   assignments on the declared seal.
2. Treat non-empty `expected_assignments` as the exact assignment selector.
3. Fail closed when a selected assignment is missing or when the exact
   `(AssignmentType, AllocatedState)` selector matches more than one assignment
   on the same seal.
4. Base input counts, sum inputs, and owner-change handling only on the selected
   assignments.
5. Add focused unit coverage for legacy all-assignment behavior and selected
   assignment behavior.
