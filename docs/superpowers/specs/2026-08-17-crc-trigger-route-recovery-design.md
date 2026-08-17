# CRC Trigger Route and Exact Incident Recovery Design

## Goal

Repair the host-side trigger routing defect that sent the CRC Flash sector
address as the UDS `RoutineControl FF00` trampoline range, then recover the
persisted attempt `20251125T181809Z` without assuming that either failed CRC
invocation changed Flash.

The first action against the ECU after installing this change is a complete,
read-only `live_read` of both 32 KiB sectors. No forward writer is authorized
from the persisted error text alone.

This change must not modify or rebuild any V850 payload, writer instruction,
FACI register sequence, erase/program primitive, sector data, CRC adjustment
word, intent layout, envelope pin, or payload result contract.

## Confirmed Evidence

The supplied state file has SHA-256
`d1e66450b31851e3ad5ef31e954d2e69f41e7743ad4322bc674f7c5c36f61581`
and contains the following audited history:

1. the target source was prechecked, armed, written, and completely read back
   as the exact target candidate;
2. the CRC source was prechecked;
3. the first CRC invocation ended at sequence 7 because the old host parser
   treated an ISO-TP frame beginning with `0x03` as a private payload frame;
4. sequence 8 then ran the read-only `live_read` payload and proved the target
   was the exact candidate and the CRC sector was still the exact source;
5. the second CRC invocation ended at sequence 10 with the explicit UDS frame
   `03 7f 31 31 00 00 00 00`, meaning RoutineControl returned NRC `0x31`
   (Request Out Of Range).

The successful reference script uploads a payload that internally operates on
the CRC sector at `0xF8000`, but triggers it through `FF00` using the fixed UDS
range `0xE0000 / 0x8000`. The migrated host instead serialized the payload's
fixed internal CRC sector, `0xF8000 / 0x8000`, into the UDS trigger request.
That conflated two independent addresses and produced the observed NRC.

NRC `0x31` is strong evidence that the requested UDS trigger range was
rejected. It is not accepted as proof of unchanged Flash. Only a new complete
`live_read` can authorize the next state.

## Separate Payload Direction from UDS Trigger Route

The specialized payload image and intent retain the actual sector direction:

- target writer/restore actual sector: `0x60000 / 0x8000`;
- CRC writer/restore actual sector: `0xF8000 / 0x8000`.

The host transport derives the UDS trigger range separately:

- target writer or target restore: `0x60000 / 0x8000`, preserving the route
  already demonstrated by the successful target commit;
- CRC writer or CRC restore: `0xE0000 / 0x8000`, matching the successful CRC
  reference implementation;
- read-only and other existing payloads: retain the existing default route
  `0x60000 / 0x8000`.

The caller may identify the specialized payload's actual sector only. It may
not supply an arbitrary trampoline address. Transport validates the exact
operation/actual-sector pairing first, then selects the allowlisted trigger
route internally. In particular, neither `OP_WRITE_CRC_CANDIDATE` nor a CRC
`OP_RESTORE_SECTOR` request may serialize `0xF8000` into `FF00`.

This host-only routing change does not affect which Flash addresses the V850
writer reads, erases, programs, or returns. Those remain fixed and independently
validated by the specialized intent and reviewed payload.

## Exact Recovery Eligibility

The ordinary two-indeterminate retry gate remains fail-closed. One narrow
legacy-recovery exception is permitted only when the audited state history has
all of these properties:

- schema 2, workflow `patch`, current result `CRC_INDETERMINATE`;
- a valid target commit and CRC precheck under the existing transition audit;
- exactly two `CRC_INDETERMINATE` transitions;
- the first is followed by a `CRC_PRECHECKED` transition whose evidence says
  `classification=source`, binds `reconciled_from=CRC_INDETERMINATE`, binds the
  first transition sequence, and contains the exact target-candidate and
  CRC-source readback hashes;
- the final transition error contains exact NRC `0x31` and exact raw frame
  `037f313100000000`;
- the immediately preceding state is the exact CRC writer arm for operation
  14, CRC base `0xf8000`, reviewed payload/envelope/intent, source hash, and
  candidate hash already enforced by the state audit;
- no later transition, PASS restore, or other mutation exists.

The exception authorizes read-only classification only. It does not directly
authorize an erase, program, retry, checkpoint edit, or success transition.
Equivalent future states may qualify only if every semantic property above is
identical; filenames, timestamps, and operator assertions are not substitutes.

## Recovery State Flow

On the first `patch` invocation with an eligible state:

1. load the fixed probe report, source backups, candidate, and reviewed
   `live_read` payload;
2. perform the existing preflight and exact bootloader identity checks;
3. run only `live_read`, which contains no FACI/erase/program capability;
4. require the complete target sector to be byte-for-byte equal to the fixed
   target candidate;
5. classify the complete CRC sector by byte-for-byte comparison:
   - **source:** persist a new `CRC_PRECHECKED` transition that binds both the
     legacy NRC recovery and the fresh hashes; persist the normal planned
     power-cycle checkpoint to `CRC_ARMED`; print the instruction and exit;
   - **candidate:** persist `CRC_COMMITTED` with the fresh hashes and a planned
     power-cycle checkpoint to final verification; no writer is run;
   - **anything else:** persist no forward state and require restore;
6. malformed streams, identity mismatch, wrong route/base/length/magic,
   non-candidate target bytes, or incomplete data all fail before any writer.

After the required power cycle, a **source** classification enters the existing
CRC writer stage. It displays the full `WRITE-CRC` transaction, requires exact
uppercase `YES`, records `CRC_ARMED`, and invokes the unchanged CRC payload
once using the corrected UDS trigger route `0xE0000 / 0x8000`.

A **candidate** classification skips the writer and resumes only the existing
read-only final verification.

If the corrected writer has any indeterminate outcome, no further forward
exception is available. The resulting history is restore-only. The legacy
NRC exception is consumed by the fresh reconciliation transition and cannot be
reused to obtain another writer.

## Restore Audit

The same routing defect exists for the generic restore payload whenever its
specialized intent targets the CRC sector. The transport fix therefore covers
both patch and restore:

- CRC restore uses UDS trigger `0xE0000` while the reviewed restore intent and
  V850 code still operate on `0xF8000`;
- target restore continues to use UDS trigger `0x60000` and operate on
  `0x60000`;
- restore keeps its fresh two-sector `live_read` before every writer arm,
  exact source backup binding, CRC-before-target order, explicit `YES`, and
  one-shot writer behavior;
- no restore state, backup, or writer payload format changes.

## Error and Persistence Rules

- RoutineControl NRCs remain explicit transport failures containing the NRC
  and all raw frame bytes.
- Because the NRC arrives after the host has sent the trigger request, it
  remains conservatively recorded as an indeterminate outcome; the host never
  infers unchanged Flash from an NRC.
- The read-only recovery transition records fresh sector hashes and the exact
  legacy transition sequence it reconciles.
- A failed or unknown live read does not mutate the incident or reduce its
  restore scope.
- No automatic retry is introduced. Every destructive stage remains a later
  invocation after a planned power cycle and exact human `YES`.
- The operator never edits `state.json`; the program audits and advances it
  atomically.

## TDD Coverage

Tests must prove:

1. target candidate writer serializes `0x60000 / 0x8000` in `FF00`;
2. CRC candidate writer validates actual sector `0xF8000` but serializes
   `0xE0000 / 0x8000` in `FF00`;
3. target restore and CRC restore select `0x60000` and `0xE0000` respectively;
4. read-only payload routes remain unchanged;
5. arbitrary operation/actual-sector/trigger combinations are rejected;
6. the supplied two-indeterminate NRC history may run exactly one read-only
   `live_read` before any state advance;
7. fresh CRC source permits the existing later exact-`YES` writer once;
8. fresh CRC candidate skips writing and reaches verification;
9. partial/unknown CRC, wrong target, malformed stream, wrong identity, or any
   near-miss history remains restore-only without state mutation;
10. after the corrected writer becomes indeterminate, another `patch`
    invocation is rejected before preflight or transport;
11. restore's CRC and target stages preserve writer order, fresh live reads,
    confirmation, intent binding, and readback verification under the new
    route;
12. all transport, patch, restore, restart-resume, state-audit, offline
    end-to-end, payload pin, and full repository tests remain green.

## Operator Contract After Release

For the supplied state, the operator performs a complete requested power cycle
and runs `python3 eps_patch.py patch` once. That invocation is read-only.

- If it reports `CRC_PRECHECKED`, perform the next requested power cycle, run
  the same command, verify the displayed `WRITE-CRC` details, and enter `YES`.
- If it reports `CRC_COMMITTED`, perform the requested power cycle and run the
  same command for read-only final verification.
- If it reports partial/unknown data or any other error, do not run `patch`
  again; use the reported restore path only after review.

No operator action is based solely on the warning lamp or DTC state. Exact
complete live bytes decide the branch.
