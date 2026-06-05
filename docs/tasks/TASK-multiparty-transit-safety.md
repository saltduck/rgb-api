# TASK: Multiparty Transit Safety Extensions

## Done

- Preserve legacy single `change_vout` behavior.
- Add owner-aware RGB input declarations.
- Add owner change vout declarations with distinct-vout validation.
- Add terminal vout declarations and ABI return occurrence mapping.
- Bind mapped ABI returns to their declared terminal seals.
- Add late-bound final tx outpoint args through the advanced API.
- Expose `commitment_txid` in multiparty transition results.
- Add tests for legacy defaults, owner mapping, distinct-vout failure,
  terminal mapping, unknown terminal failure, and late-bound arg resolution.

## Verification

- `cargo test -q`

