# Product Specification

## Multiparty Transit API

The legacy multiparty transition API remains valid:

- `MultipartyOutputPlan::new(beneficiary_vout, change_vout, carrier_vout)`
  continues to bind all `"change"` ABI returns to the single `change_vout`.
- Existing callers can keep using `build_transition_on_psbt`.
- `MultipartyTransitionInput::new(seal)` continues to consume every assignment
  found on the declared RGB input seal.

Callers can select exact assignments on a declared RGB input seal with
`MultipartyTransitionInput::with_expected_assignments(seal, assignments)`.
Non-empty `expected_assignments` are both validation criteria and the exact
assignment input set. Assignments on the same seal that are not listed must not
be consumed. Missing or ambiguous exact matches fail closed.

The extended API adds sidecar declarations on `MultipartyAdvancedTransitionPlan`:

- `with_input_owner(seal, owner_id)` for input ownership;
- `with_owner_change_vout(owner_id, vout)` for participant RGB change;
- `with_terminal_vout` and `with_assignment_terminal` for ABI return to
  terminal binding, including repeated return names such as `change#0` and
  `change#1`;
- `with_late_bound_arg(name, LateBoundArg::FinalTxOutpoint)` for arguments that
  must be resolved from the RGB commitment txid.

Late-bound construction uses cloned PSBT probes to look for a stable commitment
txid without consuming stock state. The final transition is committed to the
caller-provided PSBT only after the resolved args and RGB commitment txid
converge. If they do not converge, construction fails and the original PSBT is
left unchanged.

Example shape:

```rust
let outputs = MultipartyOutputPlan::new(Some(0), None, 4);

let base = MultipartyTransitionPlan {
    contract_id,
    transition_name: "demo".to_owned(),
    args: vec![("settler".to_owned(), "placeholder".to_owned())],
    inputs: vec![
        MultipartyTransitionInput::with_expected_assignments(
            alice_seal,
            vec![(alice_assignment_type, alice_state)],
        ),
        MultipartyTransitionInput::new(bob_seal),
    ],
    close_method,
    outputs,
};

let plan = MultipartyAdvancedTransitionPlan::new(base)
    .with_input_owner(alice_seal, "alice")
    .with_input_owner(bob_seal, "bob")
    .with_owner_change_vout("alice", 1)
    .with_owner_change_vout("bob", 2)
    .require_distinct_owner_change_vouts()
    .with_terminal_vout("alice_change", 1)
    .with_terminal_vout("bob_change", 2)
    .with_assignment_terminal(AssignmentTerminalRef::new("change", 0), "alice_change")
    .with_assignment_terminal(AssignmentTerminalRef::new("change", 1), "bob_change")
    .with_late_bound_arg("settler", LateBoundArg::FinalTxOutpoint { vout: 0 });

let result = build_advanced_transition_on_psbt(stock, psbt, &plan)?;
assert_eq!(result.witness_id, result.commitment_txid);
```

Self-referential transition scripts where the final txid argument changes the
same RGB commitment that determines that txid may not converge. Those plans must
fail closed instead of binding to a non-stable txid.
