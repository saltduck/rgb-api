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
