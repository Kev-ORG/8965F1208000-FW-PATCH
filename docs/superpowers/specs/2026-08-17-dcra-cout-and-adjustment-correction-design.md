# DCRA COUT and CRC Adjustment Correction Design

## Goal

Correct the comprehensive probe and subsequent patch payload constants for the
single supported `8965B4512000` EPS, using the complete diagnostic report from
the failed read-only probe.  The correction must preserve the existing
fail-closed workflow and must not change the reviewed FACI erase/program
sequences.

## Evidence and root cause

The recorded probe report identifies the exact target and shows that the probe
stopped at primary code `3` before the FACI P/E cycle.  Both magic words,
original DCRA residue and the pre-FACI diagnostics match the target.

Two defects explain the reported values:

1. For `DCRA1CTL=0` (the 32-bit Ethernet polynomial), the RH850 DCRA manual
   specifies that a read of `DCRA1COUT` is the stored value XOR
   `0xffffffff`.  The payload captured that read value, then wrote it back
   verbatim.  Consequently entry `0xffffffff` was restored as an exit read of
   `0x00000000`.
2. The previously pinned candidate adjustment word was not the adjustment for
   the single byte patch at `0x664e6`.  The observed hypothetical residue
   `0xf5ee5210` with `0xd1f4ce24` exactly matches the calculated error delta.
   The corrected fixed values are:

   | Meaning | Value |
   | --- | --- |
   | Original adjustment word | `0x0962887f` |
   | Patched software prefix | `0xbeb0b833` |
   | Patched adjustment word | `0x414f47cc` |
   | Expected DCRA residue | `0xffffffff` |

## Design

### DCRA state restoration

The payloads continue to capture both `DCRA1CTL` and the hardware-visible
`DCRA1COUT` before their calculation.  The common restore helper will accept
only the reviewed Ethernet configuration (`CTL & 0x3 == 0`); any other
polynomial configuration is a fail-closed payload error.  It will restore the
control value, then write `captured_cout ^ 0xffffffff` so a subsequent read
returns the captured value.  Its callers retain their current mandatory
post-restore readback comparison and error/report ordering.

The legacy CRC payload helper uses the same conversion.  No FACI unlock,
erase, program, or writer sequence is changed.

### CRC candidate constants

The immutable target manifest, host protocol validators, candidate intent
builder, and all payload source constants will use the corrected prefix and
adjustment values.  The target remains fixed to the same physical range,
original adjustment word, one-byte `0x31 -> 0x10` instruction modification,
and final residue.  Host validators will continue to reject any value outside
this exact tuple.

### Artifacts and deployment boundary

All payloads whose source changes will be rebuilt with the LAN V850 compiler.
The generated manifest, binary SHA-256 values, and 4096-byte envelope pins will
be updated together; the host refuses any stale or mismatched binary.  No
binary will be fabricated locally.  The first subsequent vehicle operation is
one read-only `probe`, which should report both original and hypothetical DCRA
residues as `0xffffffff` and exact DCRA state restoration before it can create
a trusted PASS artifact.

## Tests and acceptance criteria

- A host-side CRC linearity test derives `0x414f47cc` from the exact byte
  delta and rejects the former value.
- Source-contract tests require the documented Ethernet COUT conversion in
  both payload helpers and require fail-closed handling for another
  polynomial.
- Manifest, protocol, candidate-writer, payload binary, and documentation
  tests use the corrected immutable tuple.
- Focused tests and the complete Python 3.12 suite pass after artifacts and
  pins are reconciled.
- The rebuilt probe binary remains within the reviewed 4096-byte envelope.

## Non-goals

- No change to the public `probe`, `patch`, or `restore` command interface.
- No change to target identity, UDS routing, patch location, sector layout,
  or the reviewed FACI P/E procedures.
- No new vehicle-side diagnostic trip beyond the one read-only validation
  probe after the rebuilt artifacts are deployed.
