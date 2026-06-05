# Product Specification

## Multiparty Transit API

The legacy multiparty transition API remains valid:

- `MultipartyOutputPlan::new(beneficiary_vout, change_vout, carrier_vout)`
  continues to bind all `"change"` ABI returns to the single `change_vout`.
- Existing callers can keep using `build_transition_on_psbt`.

The extended API adds:

- `MultipartyTransitionInput::with_owner(owner_id)` for input ownership;
- `change_vouts_by_owner` on `MultipartyOutputPlan` for participant RGB change;
- `terminal_vouts` and `assignment_terminal_map` for ABI return to terminal
  binding, including repeated return names such as `change#0` and `change#1`;
- `MultipartyAdvancedTransitionPlan` with `LateBoundArg::FinalTxOutpoint` for
  arguments that must be resolved from the RGB commitment txid.

Late-bound construction uses a cloned PSBT probe to calculate the commitment
txid without consuming stock state, then rebuilds the final transition using
that txid. If the final commitment txid differs, construction fails.

Example shape:

```rust
let outputs = MultipartyOutputPlan::new(Some(0), None, 4)
    .with_owner_change_vout("alice", 1)
    .with_owner_change_vout("bob", 2)
    .require_distinct_owner_change_vouts()
    .with_terminal_vout("alice_change", 1)
    .with_terminal_vout("bob_change", 2)
    .with_assignment_terminal(AssignmentTerminalRef::new("change", 0), "alice_change")
    .with_assignment_terminal(AssignmentTerminalRef::new("change", 1), "bob_change");

let base = MultipartyTransitionPlan {
    contract_id,
    transition_name: "demo".to_owned(),
    args: vec![("settler".to_owned(), "placeholder".to_owned())],
    inputs: vec![
        MultipartyTransitionInput::new(alice_seal).with_owner("alice"),
        MultipartyTransitionInput::new(bob_seal).with_owner("bob"),
    ],
    close_method,
    outputs,
};

let plan = MultipartyAdvancedTransitionPlan::new(base)
    .with_late_bound_arg("settler", LateBoundArg::FinalTxOutpoint { vout: 0 });

let result = build_advanced_transition_on_psbt(stock, psbt, &plan)?;
assert_eq!(result.witness_id, result.commitment_txid);
```

