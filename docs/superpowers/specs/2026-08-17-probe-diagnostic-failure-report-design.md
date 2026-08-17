# Probe diagnostic failure report

## Purpose

When the comprehensive, read-only probe receives a complete ECU result whose
outcome is not PASS, retain the returned DCRA state needed to diagnose the
failure without creating trusted probe evidence or changing any ECU behavior.

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
   nonzero, it extracts only validated unsigned DCRA fields from that returned
   stream.
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
- reviewed payload name and envelope SHA-256;
- primary and cleanup outcome codes;
- `entry_ctl`, `entry_cout`, `exit_ctl`, `exit_cout`;
- original and hypothetical DCRA raw results; and
- the original non-PASS error text.

The parent `failures/` directory is separate from the trusted `probe/`
directory. Each qualifying failure replaces the previous diagnostic, so the
workflow does not accumulate intermediate artifacts.

## Boundaries

Only a complete, structurally valid comprehensive result with a nonzero
outcome receives this DCRA report. Preflight, identity, transport, payload,
and malformed-stream failures do not have trustworthy DCRA values and do not
write a synthetic report. A filesystem failure while recording the diagnostic
must not turn a non-PASS result into PASS; the operator receives the original
probe failure with an added report-write failure detail.

## Tests

Tests will demonstrate that a primary=3 result writes the fixed JSON, exposes
the six DCRA values in the raised diagnostic, creates no trusted probe
directory, and leaves the reviewed payload untouched. A PASS must leave no
diagnostic report and retain the existing atomic trusted-evidence behavior.
