# CRC Indeterminate Manual Retry Design

## Goal

Recover the current reviewed `8965B4512000` patch attempt after the CRC writer
host collector rejected an ISO-TP/UDS frame beginning with `0x03`. The workflow
must prove that the target sector is the reviewed candidate and the CRC sector
is still the reviewed source before it permits exactly one manual CRC writer
retry.

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
3. executes only the existing read-only `crc_intermediate` payload;
4. requires the complete target sector to equal the target candidate, the
   complete CRC sector to equal the CRC source, and all existing CRC/DCRA
   intermediate checks to pass;
5. persists a new `CRC_PRECHECKED` transition explicitly identifying the prior
   `CRC_INDETERMINATE` reconciliation;
6. persists the exact power-cycle checkpoint
   `CRC_PRECHECKED -> CRC_ARMED`, prints the instruction, and exits.

There is no confirmation, erase, program, or writer payload in this
invocation. If either sector differs, identity differs, evidence is malformed,
or CRC/DCRA validation fails, no writer is armed and the original
`CRC_INDETERMINATE` incident remains the authoritative recovery boundary.

### Second invocation after the planned power cycle

The existing `CRC_PRECHECKED` writer path is reused without changing its
intent or V850 code. It re-verifies the bootloader identity, displays the
complete `WRITE-CRC` transaction, requires exact uppercase `YES`, records
`CRC_ARMED`, and runs the one fixed CRC writer.

On an exact six-stage zero-status result and complete candidate readback, it
records `CRC_COMMITTED` and continues through the existing planned power-cycle
and final read-only verification path.

## One-Retry Limit

The incident history itself is the retry counter.

- One `CRC_INDETERMINATE` transition permits the read-only reconciliation and
  one subsequent manually confirmed CRC writer.
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
- A successful source reconciliation may return to `CRC_PRECHECKED` because
  the fresh complete readback has removed uncertainty about the CRC sector;
  the transition graph explicitly permits only this recovery edge.
- Existing incident binding, probe digest, transition sequence, state
  reachability, sector hashes, DCRA checks, operation lock, and no-automatic-
  retry guarantees remain enforced.

## Tests

TDD coverage will include:

1. Response Pending with nonzero padding is ignored before a valid complete
   stream.
2. A non-pending RoutineControl NRC is rejected with NRC and raw frame hex.
3. An unrelated unknown frame is rejected with raw frame hex.
4. A real schema-2 `CRC_INDETERMINATE` history with one incident performs only
   one read-only CRC intermediate payload, records `CRC_PRECHECKED`, and emits
   the exact checkpoint without confirmation.
5. Candidate, partial/other, identity-mismatched, or malformed readback never
   arms the CRC writer.
6. The following invocation runs exactly one CRC writer only after exact `YES`.
7. A second indeterminate CRC writer outcome prevents every later patch
   invocation before hardware.
8. Existing patch, restore, restart-resume, transport, protocol, offline
   end-to-end, and full repository suites remain green.

## Operator Sequence

After installing the corrected host code:

1. perform the complete requested vehicle/EPS and comma power cycle;
2. run `python3.12 eps_patch.py patch` once for read-only reconciliation;
3. verify the command reports `CRC_PRECHECKED`, saves its checkpoint, and exits;
4. perform the next complete power cycle;
5. run the same command, inspect `WRITE-CRC`, and enter exact uppercase `YES`;
6. follow the existing post-commit power-cycle and final verification prompts.

Any deviation from these named states stops the procedure.
