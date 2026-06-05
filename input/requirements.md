# Requirements

## Multiparty Transit Safety Extensions

`rgb-api` must support DApp-driven multiparty transitions where several
participants contribute RGB inputs and receive independent BTC/RGB change
outputs while preserving backward compatibility with the existing single
`change_vout` API.

The API must allow callers to declare:

- the participant owner for each RGB input;
- the RGB change output vout for each participant;
- terminal vouts and ABI return assignment mappings for transition-owned state;
- late-bound transition arguments that are resolved against a stable final
  unsigned transaction txid after the RGB commitment is written.

Unsupported or incomplete declarations must fail closed with diagnostic errors.
Callers must not provide raw commitments or bypass `rgb-api` consistency checks.
Late-bound plans that cannot converge to a stable commitment txid must also fail
closed.
