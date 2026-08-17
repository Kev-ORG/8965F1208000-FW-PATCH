# Restart-Resume Power-Cycle Design

## Goal

Make every planned vehicle/EPS/comma power cycle a durable process boundary.
`patch` and `restore` persist the completed stage, print the bilingual complete
power-cycle instruction, and exit successfully. After power is restored and
comma has rebooted, the operator reruns the same command; it reopens the same
attempt and executes only the next safe stage. `probe` remains a single-run
workflow with no planned restart-resume behavior.

This is deliberately narrower than general forward recovery. A writer that was
armed without exact committed evidence is never resumed or retried. Patch
writer uncertainty remains restore-only, and restore writer uncertainty remains
external-recovery-only.

## Considered approaches

### 1. Persisted checkpoint plus explicit manual rerun (selected)

Each planned pause records the completed state and the one permitted next state
before printing and returning. A later manual rerun of the same command is the
operator's acknowledgement that the requested complete power cycle occurred
and may execute exactly the recorded next stage.

This is the selected model because the operator explicitly controls the
vehicle/EPS/comma cycle and then reruns the command. The state machine does not
infer any additional forward progress: only the one durable, named successor is
eligible.

### 2. Persisted checkpoint plus boot-session proof

Store Linux's boot ID and require it to change before advancing. This would add
machine proof of a comma reboot, but it was rejected: the approved workflow
trusts the operator's manual rerun after the complete vehicle/comma cycle.

### 3. Explicit resume flag or token

Require `patch --resume`/`restore --resume` or a copied token. This makes intent
explicit but expands the deliberately narrow CLI and still does not prove a
power cycle. It also conflicts with the requirement to rerun the same command.

## Durable checkpoint schema

New patch and restore state files use schema 2 and add a `power_cycle` summary
field. It is either `null` or an exact object:

```json
{
  "completed_state": "TARGET_COMMITTED",
  "next_state": "CRC_PRECHECKED"
}
```

The checkpoint is written atomically as part of the normal completed-stage
state before its instruction is emitted. `completed_state` must equal the
state-file `result`. `next_state` must be one exact allowlisted successor for
that workflow state. No boot ID, resume flag, token, or CLI option is added.

`automatic_forward_resume` remains `false` in patch state, and
`automatic_retry` remains `false` in both workflows. A planned checkpoint is a
specific operator-requested restart boundary, not permission to infer or retry
an uncertain Flash outcome.

Schema-1 state remains readable for restore selection and one-shot safety. It
never authorizes restart-resume, because it lacks the explicit checkpoint and
boot-session binding.

## Invocation model

Every `patch` or `restore` invocation performs these steps in order:

1. validate static arguments, fixed payloads/templates, and trusted probe
   evidence;
2. scan the workflow's timestamped attempts and fail closed on malformed or
   contradictory state;
3. if a resumable schema-2 checkpoint exists, require that it is the only
   resumable attempt and that no successful restore has superseded it;
4. treat the manual rerun as acknowledgement of the requested complete cycle,
   run preflight, and reconstruct immutable candidates/backups from the
   fixed evidence, and execute only the checkpoint's named next stage;
5. after that stage, either persist the next planned checkpoint and return its
   `state.json`, produce the final PASS report, or persist the existing failure
   state.

The public command exits with status 0 for a planned pause. The bilingual
instruction no longer asks for Enter. The printed state path makes the durable
pause visible, while final completion still prints the workflow report path.

## Patch stage machine

One attempt directory is used across all invocations.

| Invocation entry | Work allowed in this invocation | Durable exit |
| --- | --- | --- |
| no attempt | STARTED, preflight, trusted candidate construction | `PROBED`, cycle to `TARGET_PRECHECKED` |
| rerun from `PROBED` checkpoint | target live precheck, exact target confirmation, one target writer invocation | `TARGET_COMMITTED`, cycle to `CRC_PRECHECKED` |
| rerun from `TARGET_COMMITTED` checkpoint | CRC intermediate precheck, exact CRC confirmation, one CRC writer invocation | `CRC_COMMITTED`, cycle to `VERIFY_PENDING` |
| rerun from `CRC_COMMITTED` checkpoint | persist `VERIFY_PENDING`, then perform independent final identity/live/CRC verification | `PASS` report |

The persisted transition history remains continuous across invocations. A
state without an exact planned checkpoint is never patch-resumable. In
particular, `TARGET_ARMED`, `TARGET_INDETERMINATE`, `CRC_ARMED`,
`CRC_INDETERMINATE`, and `RECOVERY_REQUIRED` always follow the existing restore
policy. An abrupt stop at an unarmed state may be abandoned, but cannot skip an
unresolved incident created after a known target commit.

If a successful restore is bound to a paused patch attempt, that patch attempt
is superseded and must never resume, even if its state-file hash later differs;
the incident timestamp is the stable binding used for this guard.

Because a planned `TARGET_COMMITTED` or `CRC_COMMITTED` checkpoint is also a
valid operator-selected restore point, live-read policy accepts only its exact
known committed state: target candidate plus CRC source for `TARGET_COMMITTED`,
or both candidates for `CRC_COMMITTED`.

## Restore stage machine

One restore attempt directory is used across all invocations. The selected
patch incident, ordered backups, completed sectors, and continuous transitions
are reconstructed and validated on every run.

For each sector in canonical order, restore executes one hardware stage per
eligible invocation:

1. RAM echo, then persist `*_ECHO_VERIFIED` and request a cycle;
2. live two-sector precheck, then persist `*_LIVE_PRECHECKED` and request a
   cycle;
3. exact confirmation plus one restore writer invocation, then persist
   `*_COMMITTED`.

After CRC commit in a two-sector restore, `CRC_COMMITTED` requests a cycle to
the exact reachable `TARGET_ECHO_VERIFIED` successor produced by the target
RAM-echo stage. After the final target-only or target commit, restore creates
the PASS report without adding a new cycle.

Only the exact checkpoint/current-sector/completed-sector combination is
resumable. `*_ARMED` and `INDETERMINATE` are never resumable. Once any restore
writer has armed, a later failure retains the current terminal
`INDETERMINATE`/external-recovery policy; restarting the command does not create
a new restore attempt or retry a writer.

## Failure and integrity rules

- Persist-before-print is mandatory. If durable checkpoint installation fails,
  no power-cycle instruction is issued.
- A single rerun consumes only one exact planned checkpoint and cannot cross a
  second planned cycle boundary.
- A missing, malformed, unsupported, duplicate, or unreachable resumable state
  fails closed.
- Payload/template/probe validation is repeated before a resumed hardware stage;
  no mutable candidate or backup is accepted from the attempt directory.
- Each destructive invocation records `*_ARMED` atomically before calling its
  writer exactly once.
- Existing writer-response loss, malformed readback, and evidence-install
  failures retain their indeterminate recovery states and never reach a planned
  checkpoint.
- Operation locking remains per invocation. Durable state, not a process-held
  lock, coordinates across reboots.

## CLI and documentation

The command surface remains exactly `probe`, `patch`, and `restore`, with only
optional `--serial`. `main()` uses a nonblocking output callback for
planned-cycle instructions. Probe does not receive a restart-resume dependency.

README instructions say to let the command exit, perform the complete
vehicle/EPS/comma power cycle, wait for comma to reboot, and rerun the same
command. They no longer instruct the operator to press Enter.

## Test strategy

Offline tests use transport fakes to prove:

- the checkpoint helper emits a bilingual non-Enter instruction;
- checkpoint state is durable before output and a prompt-output failure does
  not become writer uncertainty;
- patch uses one attempt across four invocations and performs only target,
  CRC, or verify work at the corresponding rerun stage;
- restore uses one attempt and one hardware stage per eligible invocation,
  preserving CRC-first order and completed-sector evidence;
- a changed command cannot consume another workflow's checkpoint;
- armed/indeterminate states never resume and never retry a writer;
- schema-1 incidents remain restorable but are not forward-resumable;
- probe behavior and signature contain no boot-session or power-cycle resume
  path;
- the end-to-end offline lifecycle manually reruns each workflow until it
  reaches the same final PASS evidence.

All tests run with the required Python 3.12 interpreter and perform no hardware
or network operations.

## Acceptance criteria

- Every planned patch/restore cycle persists the exact stage, prints the
  instruction, and exits with no blocked input call.
- Manually rerunning the same command after the requested complete cycle
  advances only the single allowlisted next stage in the same attempt.
- No writer invocation is repeated after an armed or uncertain outcome.
- Probe remains a one-command read-only workflow with no planned cycle.
