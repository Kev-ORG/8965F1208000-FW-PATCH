# Probe diagnostic failure report

## Purpose

When the comprehensive, read-only probe receives a complete ECU result whose
outcome is not PASS, retain one complete non-sector diagnostic summary needed
to diagnose the failure without creating trusted probe evidence or changing
any ECU behavior. The operator must be able to make this diagnosis from one
read-only probe execution rather than returning to the vehicle for separate
register, CRC, or FACI captures.

## Scope and invariants

- The ECU payload, its reviewed binary, the manifest, and its envelope pin are
  unchanged. This feature adds no ECU command and cannot introduce Flash
  erase/program behavior.
- A trusted `/data/eps-patch/artifacts/probe/` directory is still created only
  after every existing semantic PASS check succeeds.
- A failed diagnostic is not evidence. `patch` and `restore` must continue to
  reject it exactly as they reject a missing trusted probe directory.
- The feature does not relax DCRA validation: entry and exit control/count
  values must still match for PASS.

## Data flow

1. The existing payload returns its complete, CRC-valid comprehensive stream.
2. The host decodes the one outcome status. If its primary or cleanup field is
   nonzero, it extracts only validated scalar diagnostics from that returned
   stream: identity, payload identity, outcome, magic words, full DCRA record,
   all FACI snapshots, and address/length/SHA-256/CRC32 summaries of each
   returned region.
3. The host atomically replaces
   `/data/eps-patch/artifacts/failures/last-probe-failure.json`. A temporary
   sibling is fsynced and renamed; no partial final JSON is exposed.
4. `probe` still raises its normal non-PASS error. The CLI prints the four
   DCRA entry/exit values and the failure-report path as part of that error.

## Failure report contract

The fixed file contains no sector data, backups, candidate bytes, or trusted
probe report. Its exact useful content is:

- UTC creation time;
- workflow label and schema;
- ECU/Panda identity observed for this execution;
- reviewed payload name and envelope SHA-256;
- primary and cleanup outcome codes;
- both returned magic words;
- all DCRA fields: entry/exit `CTL` and `COUT`, range, adjustment address,
  original/patched adjustment words, and original/hypothetical raw results;
- all five named, width-preserving FACI snapshots returned by the payload;
- each returned region's base address, length, SHA-256, and CRC32; and
- the original non-PASS error text.

The parent `failures/` directory is separate from the trusted `probe/`
directory. Each qualifying failure replaces the previous diagnostic, so the
workflow does not accumulate intermediate artifacts.

## Boundaries

Only a complete, structurally valid comprehensive result with a nonzero
outcome receives this diagnostic report. Preflight, identity, transport,
payload, and malformed-stream failures do not have trustworthy complete data
and do not write a synthetic report. A filesystem failure while recording the
diagnostic must not turn a non-PASS result into PASS; the operator receives
the original probe failure with an added report-write failure detail.

## Tests

Tests will demonstrate that a primary=3 result writes the fixed JSON, exposes
the DCRA entry/exit values and report path in the raised diagnostic, contains
the complete scalar snapshot described above, creates no trusted probe
directory, and leaves the reviewed payload untouched. A PASS must leave no
diagnostic report and retain the existing atomic trusted-evidence behavior.
