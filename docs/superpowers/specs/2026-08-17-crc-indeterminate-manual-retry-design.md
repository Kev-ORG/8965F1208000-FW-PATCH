# CRC Indeterminate Manual Retry Design

## Goal

Recover the current reviewed `8965B4512000` patch attempt after the CRC writer
host collector rejected an ISO-TP/UDS frame beginning with `0x03`. Before any
further write, the workflow must read both complete live sectors and classify
the CRC sector as the reviewed source, the reviewed candidate, or neither.

This change does not modify any V850 source, payload binary, FACI sequence,
sector address, candidate byte, CRC adjustment, erase/program primitive, or
writer result contract.

## Observed Incident

The persisted attempt is canonically `CRC_INDETERMINATE`. Its prior read-only
`CRC_PRECHECKED` transition proved:

- target sector SHA-256 is the fixed target candidate;
- CRC sector SHA-256 is the fixed CRC source;
- the CRC intermediate payload passed its software CRC and DCRA checks.

The following `CRC_ARMED` transition sent operation 14 using the reviewed CRC
writer envelope and exact intent. No writer status or readback was persisted.
The collector instead rejected a response-route frame as `unknown frame type
0x03`, so the old observation cannot authorize another write by itself.

## UDS and Payload Stream Demultiplexing

`EcuTransport.collect_stream()` will distinguish UDS single frames from the
private V850 payload protocol before passing frames to `StreamCollector`.

- An eight-byte CAN frame whose ISO-TP single-frame length is 3 and whose UDS
  payload is `7F 31 78` is RoutineControl Response Pending. It is ignored
  regardless of bytes 4 through 7, because those are transport padding rather
  than UDS payload.
- An ISO-TP single-frame negative response `7F 31 <NRC>` with any NRC other
  than `0x78` is never ignored. Collection fails with an error containing the
  NRC and all eight raw frame bytes.
- Any other response-route frame that is neither a known payload frame nor the
  allowed pending response fails with all eight raw frame bytes in the error.
- Payload frame ordering, CRC, status, readback, route, and exact-length checks
  remain unchanged.

This corrects host parsing only. It does not reinterpret the lost writer
outcome as success.

## Manual CRC Reconciliation State Flow

The public command remains `python3.12 eps_patch.py patch`. No new public
command or evidence path is added.

### First invocation after the incident

The resume selector may select one `CRC_INDETERMINATE` attempt only when its
history contains exactly one such transition and no bound PASS restore has
superseded it. This invocation:

1. loads the same fixed probe evidence and candidate;
2. performs preflight and fresh bootloader identity verification;
3. executes only the existing reviewed `live_read` payload, which reads the
   complete target and CRC sectors and contains no FACI erase/program path;
4. requires the complete target sector to equal the fixed target candidate;
5. compares every byte of the complete CRC sector against both the fixed CRC
   source and fixed CRC candidate, then takes exactly one of these branches:
   - **source:** persists `CRC_PRECHECKED`, identifies the prior
     `CRC_INDETERMINATE` reconciliation, saves the exact power-cycle checkpoint
     `CRC_PRECHECKED -> CRC_ARMED`, prints the instruction, and exits;
   - **candidate:** performs no write, persists `CRC_COMMITTED` with the full
     live-read hashes, saves the exact power-cycle checkpoint
     `CRC_COMMITTED -> VERIFY_PENDING`, prints the instruction, and exits;
   - **other:** treats the sector as partial/unknown, persists no forward
     transition or writer checkpoint, and requires `restore`;
6. rejects malformed streams, identity mismatches, wrong magic words, wrong
   sector bases or lengths, and any target-sector value other than the exact
   candidate.

There is no confirmation, erase, program, or writer payload in this
invocation. The live-read classification is an exact byte comparison, not a
CRC32-only decision. If classification fails, no writer is armed and the
original `CRC_INDETERMINATE` incident remains the authoritative recovery
boundary.

### Second invocation after the planned power cycle

For a reconciled **source** sector, the existing `CRC_PRECHECKED` writer path
is reused without changing its intent or V850 code. It re-verifies the
bootloader identity, displays the complete `WRITE-CRC` transaction, requires
exact uppercase `YES`, records `CRC_ARMED`, and runs the one fixed CRC writer.

On an exact six-stage zero-status result and complete candidate readback, it
records `CRC_COMMITTED` and continues through the existing planned power-cycle
and final read-only verification path.

For a reconciled **candidate** sector, the invocation resumes from
`CRC_COMMITTED` and runs the existing final read-only CRC/DCRA verification
path. It never displays `WRITE-CRC` and never runs a writer.

## One-Retry Limit

The incident history itself is the retry counter.

- One `CRC_INDETERMINATE` transition permits one read-only reconciliation. A
  source result permits one subsequent manually confirmed CRC writer; a
  candidate result permits no writer and advances only to final verification.
- If that writer also becomes `CRC_INDETERMINATE`, the history contains two
  such transitions. Patch resume rejects it before preflight, transport, or
  confirmation. There is no third CRC writer attempt.
- `automatic_retry` remains `false`; the retry requires a new invocation, a
  fresh read-only proof, a planned complete power cycle, and a new human `YES`.

## Error Handling and Persistence

- A UDS NRC other than `0x78` is reported as UDS evidence, not as an unknown
  payload frame.
- All invalid payload frames include raw frame hex for diagnosis.
- A failed reconciliation never shrinks the persisted restore scope and never
  creates a writer checkpoint.
- A successful source reconciliation may return to `CRC_PRECHECKED`; a
  successful candidate reconciliation may advance to `CRC_COMMITTED`. The
  transition graph permits exactly those two recovery edges from a single
  `CRC_INDETERMINATE` history.
- A partial/unknown CRC sector remains restore-only. The existing restore
  workflow already permits `CRC_INDETERMINATE` with target=candidate and
  CRC=source/candidate/other, restoring CRC before target.
- Existing incident binding, probe digest, transition sequence, state
  reachability, sector hashes, DCRA checks, operation lock, and no-automatic-
  retry guarantees remain enforced.

## Tests

TDD coverage will include:

1. Response Pending with nonzero padding is ignored before a valid complete
   stream.
2. A non-pending RoutineControl NRC is rejected with NRC and raw frame hex.
3. An unrelated unknown frame is rejected with raw frame hex.
4. A real schema-2 `CRC_INDETERMINATE` history with a source CRC sector runs
   only `live_read`, records `CRC_PRECHECKED`, and emits the exact checkpoint
   without confirmation.
5. A complete candidate CRC sector runs only `live_read`, records
   `CRC_COMMITTED`, and reaches final verification after the next power cycle
   without any writer or confirmation.
6. A partial/other CRC sector, non-candidate target sector,
   identity-mismatched result, or malformed readback never arms a writer and
   remains restore-only.
7. The invocation following a source classification runs exactly one CRC
   writer only after exact `YES`.
8. A second indeterminate CRC writer outcome prevents every later patch
   invocation before hardware.
9. Existing patch, restore, restart-resume, transport, protocol, offline
   end-to-end, and full repository suites remain green.

## Operator Sequence

After installing the corrected host code:

1. perform the complete requested vehicle/EPS and comma power cycle;
2. run `python3.12 eps_patch.py patch` once for read-only reconciliation;
3. inspect the reported classification:
   - `CRC_PRECHECKED`: the CRC sector is exactly the source; perform the next
     complete power cycle, run the same command, inspect `WRITE-CRC`, and enter
     exact uppercase `YES`;
   - `CRC_COMMITTED`: the CRC sector is already exactly the candidate; perform
     the next complete power cycle and run the same command for final verify;
   - partial/unknown error: do not run `patch` again; run `restore`;
4. follow the existing post-commit power-cycle and final verification prompts.

Any deviation from these named states stops the procedure.
