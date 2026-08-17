# Bilingual Human-Facing README Redesign

Date: 2026-08-17

Status: user-approved design

## Goal

Rewrite the repository README for human operators and RH850 bench researchers.
The document must lead with a complete English version and then provide a
complete Chinese version. Both versions use the same numbered chapters, carry
the same commands and safety boundaries, and describe only behavior implemented
by the current repository.

## Document Structure

The README begins with the project title and two anchor links. It then contains:

```text
English
0. Risk Warning
1. Detailed Operating Guide
2. Design Principles and How It Works
3. Cross-Compilation and Porting to Other Bench ECUs
4. FAQ

中文
0. 风险警告
1. 详细操作指南
2. 脚本设计原则和工作原理
3. 交叉编译环境与其他台架车型移植
4. 常见问题
```

English is complete and appears first. Chinese is a complete translation rather
than a summary. Headings, command examples, state names, addresses, hashes,
stop conditions, and FAQ coverage remain semantically aligned.

## Chapter 0: Risk Warning

Both languages must state:

- this repository supports only the reviewed stationary bench EPS
  `8965B4512000` and is not a general flasher;
- Flash erase/program can leave the EPS unavailable and requires stable power,
  a recoverable original backup, and a realistic external recovery plan;
- unexpected power loss during a writer is outside the supported workflow and
  must be treated as an indeterminate outcome, not retried automatically;
- `patch` and `restore` require a visible foreground interactive SSH TTY;
- operators must never edit, replace, select, or manufacture `state.json`,
  reports, backups, incidents, sectors, or payload binaries;
- DTCs, steering feel, terminal silence, SSH loss, or one UDS response cannot
  substitute for a complete validated readback and PASS report;
- road testing, arbitrary targets, and automatic retries are outside scope.

## Chapter 1: Detailed Operating Guide

The guide starts from a clean laptop checkout and includes:

1. rsync into `/data/eps-patch/app/`, excluding caches, virtual environments,
   Git metadata, tests, and internal design records while leaving the sibling
   fixed artifact directory `/data/eps-patch/artifacts/` untouched;
2. verification of Python 3.12, required imports, foreground TTY, stable power,
   and absence of `pandad`/openpilot processes before every invocation;
3. the exact public commands:
   `python3.12 eps_patch.py probe`,
   `python3.12 eps_patch.py patch`, and
   `python3.12 eps_patch.py restore`;
4. probe PASS artifacts and the separate untrusted failed-probe diagnostic;
5. the normal patch sequence, one payload per invocation, every planned
   checkpoint, complete vehicle/EPS/comma power cycle, SSH reconnection, and
   rerunning the same command;
6. exact uppercase `YES` semantics and the fields an operator must review;
7. final PASS requirements and a result/action table covering
   `TARGET_INDETERMINATE`, `CRC_INDETERMINATE`,
   `RECOVERY_REQUIRED`, partial/unknown live state, and PASS;
8. the narrow reviewed CRC reconciliation exception without presenting it as a
   general retry mechanism;
9. restore discovery, fresh two-sector live read before each writer, CRC-before-
   target order when both sectors are involved, separate power-cycle stages,
   and external-recovery stop conditions;
10. preservation of complete artifacts after PASS or failure.

The guide explicitly says that comma loses power with the vehicle: no operator
presses Enter in a dead SSH session. The command saves state and exits; after
power returns, the operator reconnects and runs the same command again.

## Chapter 2: Design Principles and How It Works

Both languages explain:

- the intentionally minimal `probe`, `patch`, and `restore` interface;
- fixed semantic evidence instead of a hard-coded report-file hash;
- exact identity, application/boot F181, Panda, manifest, payload, intent,
  sector, and state-history bindings;
- the 4 KiB encrypted envelope at `0xFEBF0000` and fixed FF00 trigger range
  `0xE0000 / 0x8000`;
- the distinction between the trigger range and actual target/CRC sectors
  `0x60000` and `0xF8000`;
- ECU-local 32 KiB read-modify-write, with no 32 KiB host upload;
- one payload and one UDS/Panda connection per invocation;
- read-only prechecks separated from destructive writers by persisted
  checkpoints and complete power cycles;
- exact fixed-direction FACI erase/program operations, bounded waits, status
  checks, cleanup, exit-idle validation, full readback, and no writer retry;
- target instruction `0x664E6: 0x31 -> 0x10`, CRC adjustment at `0xFFDEC`,
  software CRC and DCRA verification, and why both sectors are required;
- atomic/fsynced evidence, immutable history, incident gates, and restore order;
- the difference between Flash-level PASS and a later stationary functional
  compatibility test of the RX SecOC behavior.

## Chapter 3: Cross-Compilation and Porting

### Current repository build

Document:

```bash
docker build -t v850-gcc:latest v850-cross-build

docker run --rm \
  -v "$PWD/payload:/src" \
  -w /src \
  v850-gcc:latest \
  sh -c 'TOOL_PREFIX=v850-elf- ./build.sh'
```

Explain that the image contains Ubuntu 22.04, binutils 2.41, GCC 13.2.0, and the
`v850-elf` toolchain. The repository continues to own `payload/build.sh`.
Building regenerates retained binaries and `manifest.json`; it must be done in
a clean review branch, followed by size, source binding, binary SHA-256,
envelope SHA-256, disassembly, forbidden-address, focused-test, and full-test
review. The image is not built on comma and a casual rebuild must not be synced
to the bench.

### Forking for another RH850 bench target

State that the general research method is likely similar across related RH850
platforms, but none of the current target-specific values are portable. A fork
must independently establish and test:

- exact ECU part number, firmware revision, endianness, image base, and address
  mapping;
- UDS IDs, bus, session order, timing, old/new variant, SecurityAccess
  algorithm/secret, DID prerequisites, RequestDownload format, RAM allocation,
  authentication routine, and FF00 trigger behavior;
- bootloader exploit entry, runtime stubs, stack, watchdog, CAN transmit
  registers, SRAM buffer, and payload size constraints;
- Code Flash geometry, sector/block/page sizes, FACI register addresses,
  access widths, protection unlock, entry/exit order, command protocol, error
  masks, polling, cleanup, and reset behavior;
- the actual firmware control-flow decision found through disassembly and bench
  evidence rather than copying `0x664E6`;
- every boot integrity mechanism, including CRC/DCRA descriptors, coverage,
  seed, polynomial, byte/word order, adjustment words, signatures, or secure
  boot;
- read-only probe evidence and exact original backups before any destructive
  experiment;
- independently reviewed fixed-direction patch and restore primitives, with
  recovery proven before patching;
- new manifests, binary/envelope pins, source contracts, protocol tests, fault
  models, artifact roots, target names, and documentation;
- disposable/stationary bench validation and access to an external programmer.

The README must never imply that V850 build compatibility makes the current
addresses, shellcode, credentials, payloads, or recovery data compatible with
another RH850 ECU.

## Chapter 4: FAQ

Both languages include matched questions and answers covering at least:

1. Why did SSH disappear after a requested power cycle?
2. Should I press Enter after comma loses power?
3. Why does one command execute only one payload?
4. What does the uppercase `YES` authorize?
5. Is terminal silence proof that Flash programming is still running?
6. What is `7F 31 78`, and why can a frame start with `0x03`?
7. Does NRC `0x31`, a timeout, or a broken stream prove whether Flash changed?
8. Can steering DTCs or assist behavior determine CRC-sector state?
9. What should I do after `TARGET_INDETERMINATE`?
10. What should I do after `CRC_INDETERMINATE`?
11. Why is one historical CRC reconciliation allowed but not a general retry?
12. Can I edit or replace `state.json` to continue?
13. Can I rerun probe after a trusted PASS directory exists?
14. Why is restore CRC-before-target when both sectors may be affected?
15. What if restore becomes indeterminate?
16. What if unexpected external power loss occurs during erase/program?
17. Why is RequestDownload 4 KiB rather than 32 KiB?
18. Why does the transaction show `0x60000`/`0xF8000` while FF00 uses
    `0xE0000`?
19. Does patch PASS prove RX SecOC is functionally bypassed on the bench?
20. Can I rebuild payload binaries and immediately use them?
21. Can this repository be used unchanged on another RH850 EPS?
22. What evidence should be preserved after success or failure?

Answers are direct, operator-oriented, and consistent with the current state
machine. They do not invent automatic recovery paths.

## Validation

The rewrite must:

- preserve every current documentation contract checked by
  `tests/test_documentation.py`;
- add documentation tests for English-first ordering, the exact 0–4 chapters,
  Docker commands, RH850 non-portability warnings, rsync artifact protection,
  re-SSH/rerun instructions, and FAQ recovery coverage;
- reject stale Enter-only power-cycle guidance, generic retry language, or any
  instruction to edit incident state;
- run documentation-focused tests and the complete repository test suite;
- make no production-code, payload, binary, or manifest change.

