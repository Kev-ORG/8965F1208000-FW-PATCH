# EPS Patch Migration Design

## Goal

Migrate the useful parts of the existing 8965B4512000 EPS patch tool into a
clean Git repository. The comma device runs the complete workflow locally; no
report or backup needs to be downloaded to a computer, assigned a hard-coded
hash, and uploaded again.

The public CLI has exactly three commands:

```bash
python3.12 eps_patch.py probe
python3.12 eps_patch.py patch
python3.12 eps_patch.py restore
```

## Operating constraints

- The tool targets only the reviewed `8965B4512000` EPS and fails closed for
  any mismatched identity or unsupported live state.
- Hardware operations run on the comma device with the required openpilot,
  Panda, UDS, and cryptography runtime available.
- Probe and patch are separate operator actions. A successful probe does not
  continue into a write operation.
- Flash erase/program operations are never retried automatically.
- A UDS reset is not accepted as a substitute for a complete EPS/vehicle power
  cycle.
- The patch still updates both the target sector at `0x60000` and the boot CRC
  sector at `0xF8000`; the prior one-sector patch remains unsupported.

## User-facing workflows

### `probe`

`probe` runs one comprehensive payload. It subsumes the old normal probe and
unlock-only probe while retaining the complete P/E-cycle diagnostic:

1. Read and validate ECU identity.
2. Read both original sectors required for patching and recovery.
3. Validate magic words and the exact original instruction context.
4. Verify the initial FACI idle state.
5. Exercise and observe `PRE -> UNLOCKED -> WINDOWS -> CONFIGURED -> RESTORED`.
6. Require exact cleanup back to the initial idle state.
7. Atomically install the PASS report, original sector backups, and recovery
   metadata into the fixed probe directory.

The command performs no Flash erase or program operation. The fixed probe
directory must not already exist, preventing silent replacement of trusted
recovery evidence.

### `patch`

`patch` accepts no report path and no probe directory option. It automatically
loads the fixed comma-local probe evidence, validates the evidence semantically,
then rechecks current ECU identity and live Flash before any write.

It writes the target sector and boot CRC sector in the reviewed order. Before
each required complete power cycle, the script prints a prominent bilingual
instruction explaining that vehicle/EPS power must be removed and waits for the
operator to press Enter after completing the cycle. A power-cycle checkpoint
uses simple Enter confirmation. Each destructive Flash write retains a precise
confirmation string bound to the current source, candidate, address, staged
CRC, and payload.

Every attempt receives a new timestamped directory and state file. Once an
erase/program operation is armed, missing or ambiguous output is recorded as
`INDETERMINATE`; the command stops and directs the operator to `restore` rather
than retrying.

### `restore`

`restore` accepts no backup path. It loads the fixed original sector backups
and the most recent incomplete or failed patch state. That state determines the
minimum safe recovery action:

- If only the target sector may have been modified, restore only the target
  sector.
- If both sectors may have been modified, restore the CRC sector first, require
  a complete power cycle, and then restore the target sector.

Before each recovery write, restore validates ECU identity, backup structure,
live state, and the exact recovery direction. It requires a destructive
confirmation bound to the current incident and backup. Power-cycle checkpoints
use the same prominent prompt and Enter confirmation as patch.

An indeterminate restore is never retried automatically. The command preserves
its report and directs the operator to an external programmer or professional
recovery path.

## Evidence layout

Runtime evidence lives outside the source checkout:

```text
/data/eps-patch/artifacts/
├── probe/
│   ├── faci-pe-cycle-report.json
│   ├── original-sector-0x60000.bin
│   ├── original-sector-0xf8000.bin
│   └── recovery-metadata.json
├── patch/
│   └── <UTC timestamp>/
│       ├── patch-report.json
│       ├── state.json
│       └── <required readback evidence>
└── restore/
    └── <UTC timestamp>/
        ├── restore-report.json
        ├── state.json
        └── <required readback evidence>
```

The implementation uses constants for the root and fixed probe directory so
tests can inject a temporary artifact root without exposing path selection as a
normal user option.

## Trust model

The implementation removes the hard-coded SHA-256 of one reviewed
`faci-pe-cycle-report.json`. Trust comes from semantic validation plus fresh
hardware checks, not from moving one exact JSON serialization through a
developer workstation.

Before patch is allowed, all of the following must hold:

- `faci-pe-cycle-report.json` exists, parses as JSON, and has the supported
  schema.
- `workflow` is `faci-pe-cycle` and `result` is `PASS`.
- Identity, part number, UDS variant, sector address, and sector length fields
  are complete and target-compatible.
- Both backup files exist, have the exact expected lengths and instruction
  context, and agree with the report and recovery metadata.
- FACI checkpoints contain the complete `PRE`, `UNLOCKED`, `WINDOWS`,
  `CONFIGURED`, and `RESTORED` sequence with the reviewed register values.
- The raw outcome and cleanup code are zero and `validation_errors` is empty.
- `RESTORED` exactly matches `PRE`.
- A fresh connection proves that the current ECU identity matches the report
  and that current live sectors are in a state permitted for the requested
  operation.

The comma may dynamically calculate hashes of backup binaries, candidates,
payloads, intents, readbacks, and state files to detect corruption and bind an
attempt together. These hashes are generated and consumed locally. The removed
mechanism is the source-code constant that accepts only one preselected report
file hash.

## Power-cycle interaction

When a complete power cycle is required, the script:

1. Prints an attention banner naming the current and next workflow states.
2. Instructs the operator to switch off vehicle/EPS power, wait for complete
   discharge, restore stable power, and not substitute a UDS reset.
3. Waits for Enter.
4. Reconnects and revalidates ECU identity and the expected live state.

Pressing Enter records only the operator checkpoint. It never replaces the
fresh post-cycle hardware validation.

## Failure model

- Probe failure produces a FAIL report but never installs a trusted probe
  directory and therefore cannot authorize patch.
- Failure before a writer is armed stops safely without requesting restore.
- Failure after a writer is armed records the applicable target or CRC sector
  as indeterminate and prohibits another patch attempt.
- Failure after a successful target commit records that recovery is required
  even if later evidence installation or verification fails.
- Restore selects its order from persisted state, not from operator memory.
- Missing, malformed, contradictory, or stale evidence fails closed with an
  actionable error.

## Repository migration scope

Keep only files needed to understand, build, test, and run the three workflows:

- Python CLI and focused runtime modules.
- C payload sources and headers used by the comprehensive probe, the two fixed
  writers, readback/verification, and recovery.
- Linker files and build scripts required to reproduce shipped payloads.
- Required runtime payload binaries and their reproducible manifest if comma
  cannot build them locally.
- Tests for retained behavior.
- README and concise safety/root-cause documentation.
- Packaging metadata and `.gitignore`.

Do not migrate `.venv`, `.pytest_cache`, `__pycache__`, `.DS_Store`, local
artifacts, obsolete one-sector workflows, superseded probe payloads, or
rebuildable compiler intermediates such as objects, ELF files, maps,
disassemblies, symbol dumps, section dumps, and preprocessed sources.

## Test strategy

Automated tests must prove:

- The CLI exposes exactly `probe`, `patch`, and `restore`.
- One comprehensive probe covers backup, identity, FACI unlock, write windows,
  P/E entry, cleanup, and PASS report installation.
- No hard-coded PASS report hash is present or consulted.
- Patch and restore automatically discover the fixed local evidence.
- Missing, malformed, forged, incomplete, mismatched, or FAIL reports are
  rejected before hardware side effects.
- Backup corruption, wrong ECU identity, and unsafe live sector states are
  rejected.
- Power-cycle prompts block for Enter and are followed by fresh hardware
  validation.
- Destructive confirmation remains mandatory for patch and restore writers.
- State at each possible patch interruption produces the correct restore scope
  and sector order.
- Indeterminate writers are not automatically retried.
- Source-control hygiene excludes caches, runtime evidence, and rebuildable
  build intermediates.

Where hardware is unavailable, transport fakes exercise complete workflow and
failure transitions. Payload source-contract tests enforce reviewed addresses,
store order, bounded polling, cleanup, and forbidden retry/erase behavior.

## Acceptance criteria

- A user with only a comma device can run probe, later run patch, and recover a
  failed patch without transferring evidence through a computer.
- Exactly one probe payload execution is required.
- Patch is authorized by a locally generated, semantically valid PASS report
  plus fresh ECU checks, not a prewritten report hash.
- Every required complete power cycle is explicitly prompted and acknowledged.
- Recovery is a first-class command and automatically chooses the safe scope
  and order from persisted evidence.
- The new Git repository contains no caches, local evidence, virtual
  environment, or rebuildable compiler intermediates.
