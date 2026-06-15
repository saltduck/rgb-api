# TASK-001: Multiparty Input Assignment Selection

## Status

Done

## Owner

Codex

## Source

`docs/migration-report.md`

## Objective

Allow callers to consume only the assignment(s) listed in
`MultipartyTransitionInput::expected_assignments` while preserving legacy
all-assignment consumption when the list is empty.

## Scope

- Update the multiparty transition builder input selection path.
- Keep `build_transition_on_psbt` and `build_advanced_transition_on_psbt`
  behavior aligned through their shared inner builder.
- Add focused unit tests for selection semantics.

## Out Of Scope

- Changing public struct fields.
- Adding a new advanced sidecar selector API.
- Changing `RgbWallet::transit` or invoice-driven payment selection.

## Dependencies

- Existing `MultipartyTransitionInput::expected_assignments` field.

## Implementation Checklist

- [x] Preserve legacy behavior for empty `expected_assignments`.
- [x] Consume only selected assignments when `expected_assignments` is non-empty.
- [x] Fail closed for missing or ambiguous selected assignments.
- [x] Add focused tests.
- [x] Run targeted verification.

## Acceptance Criteria

- Empty `expected_assignments` consumes all assignments on the input seal.
- Non-empty `expected_assignments` consumes only exact matching assignments.
- Missing or ambiguous exact matches return diagnostic errors.
- Both public multiparty builders inherit the behavior from the shared inner
  builder.

## Verification

- `cargo test -q multiparty`
- `cargo test -q`
