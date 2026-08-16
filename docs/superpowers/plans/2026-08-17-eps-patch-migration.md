# EPS Patch Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a clean comma-local 8965B4512000 EPS tool with exactly `probe`, `patch`, and `restore`, one comprehensive probe, semantic PASS-report validation, fixed evidence discovery, explicit power-cycle prompts, and automatic recovery selection.

**Architecture:** Migrate the proven transport, protocol, CRC, fixed-writer, and recovery primitives, then put a small three-command CLI over three focused workflow modules. A new evidence module owns the fixed `/data/eps-patch/artifacts` layout and semantic trust boundary; patch and restore reuse the reviewed two-sector mechanics but no longer expose their internal phase-oriented commands.

**Tech Stack:** Python 3.12, pytest, C99 V850 payload sources, pycryptodome, Panda/openpilot UDS runtime.

## Global Constraints

- Public CLI commands are exactly `probe`, `patch`, and `restore`.
- Runtime evidence defaults to `/data/eps-patch/artifacts`; tests inject another root without adding a user-facing path option.
- Probe executes one comprehensive payload and performs no Flash erase/program operation.
- Patch and restore accept no report, probe-directory, backup, incident, or output path arguments.
- A hard-coded SHA-256 of `faci-pe-cycle-report.json` is forbidden.
- Locally generated hashes remain required for binary integrity, candidates, payloads, intents, readbacks, and attempt-state binding.
- Complete power-cycle checkpoints use a prominent bilingual prompt and wait for Enter; destructive writers retain exact bound confirmation strings.
- Flash erase/program operations never retry automatically.
- The tool remains locked to `8965B4512000`, target sector `0x60000`, CRC sector `0xF8000`, and the reviewed two-sector patch.
- Source control excludes virtual environments, caches, runtime artifacts, and rebuildable compiler intermediates.

---

## File Structure

- `eps_patch.py`: parse exactly three public commands, construct dependencies, and dispatch.
- `eps_patch/paths.py`: fixed artifact layout, timestamped attempt paths, and test-injectable root.
- `eps_patch/evidence.py`: atomic probe installation and strict semantic loading of trusted PASS evidence.
- `eps_patch/probe.py`: one comprehensive read-only probe workflow.
- `eps_patch/patch.py`: two-sector patch orchestration and persisted incident state.
- `eps_patch/restore.py`: incident discovery, restore-plan selection, and ordered recovery orchestration.
- `eps_patch/power.py`: bilingual power-cycle checkpoint interaction.
- `eps_patch/{manifest,artifacts,crc,candidate_writer,crc_artifacts,payload,preflight,protocol,transport}.py`: retained reviewed primitives, narrowed only where old public workflows leak through.
- `payload/`: only the comprehensive probe, three readback/verification payloads, two candidate writers, RAM echo, restore writer, common headers, linker inputs, build script, retained `.bin` files, and manifest.
- `tests/`: focused unit, source-contract, workflow, fault-model, payload-integrity, and offline end-to-end tests for retained behavior.

### Task 1: Clean repository skeleton and retained primitives

**Files:**
- Create: `.gitignore`
- Create: `pyproject.toml`
- Create: `eps_patch/__init__.py`
- Create: `eps_patch/manifest.py`
- Create: `eps_patch/artifacts.py`
- Create: `eps_patch/crc.py`
- Create: `eps_patch/candidate_writer.py`
- Create: `eps_patch/crc_artifacts.py`
- Create: `eps_patch/payload.py`
- Create: `eps_patch/preflight.py`
- Create: `eps_patch/protocol.py`
- Create: `eps_patch/transport.py`
- Create: `tests/test_repository_hygiene.py`
- Create: `tests/test_manifest.py`
- Create: `tests/test_crc.py`
- Create: `tests/test_protocol.py`
- Create: `tests/test_transport.py`

**Interfaces:**
- Consumes: reviewed implementations from the source tree.
- Produces: importable `eps_patch` primitives used by every later task.

- [ ] **Step 1: Write the repository-hygiene failing test**

```python
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_repository_contains_no_local_or_rebuildable_outputs():
  forbidden = {".DS_Store", ".pytest_cache", "__pycache__", ".venv"}
  assert not [path for path in ROOT.rglob("*") if path.name in forbidden]
  forbidden_suffixes = {".o", ".elf", ".map", ".disassembly", ".symbols", ".sections", ".preprocessed"}
  assert not [path for path in (ROOT / "payload").rglob("*") if path.suffix in forbidden_suffixes]
```

- [ ] **Step 2: Run the skeleton test and verify it fails**

Run: `python3.12 -m pytest tests/test_repository_hygiene.py -v`

Expected: FAIL because the package and migrated clean tree do not exist yet.

- [ ] **Step 3: Migrate the primitive modules and baseline tests**

Copy only the listed primitive source files and their directly relevant tests, change imports from `sienna_secoc` to `eps_patch`, and set packaging metadata:

```toml
[project]
name = "eps-patch"
version = "0.1.0"
requires-python = ">=3.12,<3.13"
dependencies = ["pycryptodome>=3.20"]

[project.optional-dependencies]
test = ["pytest>=8"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers"
```

Use `.gitignore` entries for `.DS_Store`, `.venv/`, `.pytest_cache/`, `__pycache__/`, `*.pyc`, `/artifacts/`, and rebuildable payload outputs while explicitly allowing retained `payload/build/*.bin` and `payload/build/manifest.json`.

- [ ] **Step 4: Run primitive and hygiene tests**

Run: `python3.12 -m pytest tests/test_repository_hygiene.py tests/test_manifest.py tests/test_crc.py tests/test_protocol.py tests/test_transport.py -v`

Expected: PASS.

- [ ] **Step 5: Commit the clean foundation**

```bash
git add .gitignore pyproject.toml eps_patch tests
git commit -m "chore: migrate reviewed eps patch primitives"
```

### Task 2: Fixed artifact layout and semantic probe evidence

**Files:**
- Create: `eps_patch/paths.py`
- Create: `eps_patch/evidence.py`
- Create: `tests/test_paths.py`
- Create: `tests/test_evidence.py`

**Interfaces:**
- Consumes: `TargetManifest`, `EcuIdentity`, `sha256_bytes`, and FACI diagnostic definitions.
- Produces: `ArtifactLayout`, `TrustedProbeEvidence`, `install_probe_pass(layout, target_sector, crc_sector, report, metadata) -> Path`, and `load_probe_pass(layout, target) -> TrustedProbeEvidence`.

- [ ] **Step 1: Write failing fixed-layout tests**

```python
from pathlib import Path
from eps_patch.paths import ArtifactLayout

def test_fixed_layout_uses_one_probe_and_timestamped_attempts(tmp_path: Path):
  layout = ArtifactLayout(tmp_path)
  assert layout.probe_report == tmp_path / "probe/faci-pe-cycle-report.json"
  assert layout.target_backup == tmp_path / "probe/original-sector-0x60000.bin"
  assert layout.crc_backup == tmp_path / "probe/original-sector-0xf8000.bin"
  assert layout.patch_attempt("20260817T010203Z") == tmp_path / "patch/20260817T010203Z"
  assert layout.restore_attempt("20260817T010204Z") == tmp_path / "restore/20260817T010204Z"
```

- [ ] **Step 2: Write failing semantic-trust tests**

Create a valid report fixture with `workflow="faci-pe-cycle"`, `result="PASS"`, zero outcome/cleanup, empty validation errors, the five exact snapshots, both sector descriptors, identity, and UDS variant. Assert that `load_probe_pass(layout, TARGET)` succeeds without a fixed report digest. Parametrize rejection for missing file, malformed JSON, `FAIL`, wrong part number, missing checkpoint, nonzero cleanup, changed instruction context, wrong backup size, and backup/report mismatch.

```python
@pytest.mark.parametrize("mutation", [
  lambda r: r.update(result="FAIL"),
  lambda r: r["outcome"].update(cleanup_code=1),
  lambda r: r["snapshots"].pop("RESTORED"),
])
def test_semantic_loader_rejects_non_pass_evidence(valid_probe, mutation):
  layout, report = valid_probe
  mutation(report)
  write_report(layout.probe_report, report)
  with pytest.raises(EvidenceError):
    load_probe_pass(layout, TARGET)
```

- [ ] **Step 3: Run evidence tests and verify they fail**

Run: `python3.12 -m pytest tests/test_paths.py tests/test_evidence.py -v`

Expected: FAIL with missing `eps_patch.paths` and `eps_patch.evidence`.

- [ ] **Step 4: Implement paths and semantic validation**

Define:

```python
DEFAULT_ARTIFACT_ROOT = Path("/data/eps-patch/artifacts")

@dataclass(frozen=True)
class ArtifactLayout:
  root: Path = DEFAULT_ARTIFACT_ROOT
  # properties: probe_directory, probe_report, target_backup, crc_backup,
  # recovery_metadata, patch_root, restore_root

@dataclass(frozen=True)
class TrustedProbeEvidence:
  identity: EcuIdentity
  target_sector: bytes
  crc_sector: bytes
  report: dict[str, object]
```

`install_probe_pass` must stage all four files in a sibling temporary directory, fsync files and directory, reject an existing final probe directory, then atomically rename the completed directory. `load_probe_pass` must parse and validate exact required fields, dynamic backup hashes, lengths, addresses, original instruction context, exact FACI checkpoint semantics, zero outcome/cleanup, and empty validation errors. It must not compare report bytes against a source-code hash constant.

- [ ] **Step 5: Run evidence tests**

Run: `python3.12 -m pytest tests/test_paths.py tests/test_evidence.py -v`

Expected: PASS.

- [ ] **Step 6: Commit the local trust boundary**

```bash
git add eps_patch/paths.py eps_patch/evidence.py tests/test_paths.py tests/test_evidence.py
git commit -m "feat: validate comma-local probe evidence"
```

### Task 3: One comprehensive probe

**Files:**
- Create: `eps_patch/probe.py`
- Create: `payload/probe_pe_cycle.c`
- Create: retained common payload headers/linker/build files
- Create: `payload/build/probe_pe_cycle.bin`
- Modify: `payload/build/manifest.json`
- Create: `tests/test_probe.py`
- Create: `tests/test_pe_cycle_source_contracts.py`
- Create: `tests/test_payload_binaries.py`

**Interfaces:**
- Consumes: `ArtifactLayout`, `PayloadImage`, `EcuTransport`, `install_probe_pass`, and target manifest.
- Produces: `run_probe(*, layout, payload, preflight, transport_factory, target, new_uds) -> Path`.

- [ ] **Step 1: Write the failing single-execution workflow test**

```python
def test_probe_runs_one_payload_and_installs_pass(layout, fake_transport, probe_payload):
  result = run_probe(
    layout=layout, payload=probe_payload, preflight=lambda: None,
    transport_factory=lambda: fake_transport, target=TARGET, new_uds=False,
  )
  assert fake_transport.operations == [OP_FACI_PE_CYCLE]
  assert result == layout.probe_report
  assert load_probe_pass(layout, TARGET).report["result"] == "PASS"
```

Add cases proving no artifact installation on nonzero primary/cleanup, incomplete diagnostics, non-idle PRE, RESTORED mismatch, wrong identity, wrong target-sector content, or wrong CRC-sector content.

- [ ] **Step 2: Run probe tests and verify they fail**

Run: `python3.12 -m pytest tests/test_probe.py tests/test_pe_cycle_source_contracts.py -v`

Expected: FAIL because the consolidated workflow and migrated payload are absent.

- [ ] **Step 3: Implement the consolidated probe**

Adapt the reviewed P/E-cycle payload so one execution returns both required full sectors plus magic, CRC/DCRA evidence, and all 40 FACI diagnostics. Preserve bounded polls, stage-aware cleanup, exact original context checks, and the prohibition on FACI erase/program commands. `run_probe` validates stream, identity, two sectors, CRC observation, five snapshots, and outcome before calling `install_probe_pass`.

- [ ] **Step 4: Build and retain only the probe runtime binary**

Run the existing reviewed cross-build path for `probe_pe_cycle`; place only `probe_pe_cycle.bin` and its manifest entry under `payload/build/`. Update the binary test to check its size, SHA-256, entrypoint, and reviewed source-to-manifest binding.

- [ ] **Step 5: Run probe and payload tests**

Run: `python3.12 -m pytest tests/test_probe.py tests/test_pe_cycle_source_contracts.py tests/test_payload_binaries.py -v`

Expected: PASS.

- [ ] **Step 6: Commit one-probe support**

```bash
git add eps_patch/probe.py payload tests/test_probe.py tests/test_pe_cycle_source_contracts.py tests/test_payload_binaries.py
git commit -m "feat: consolidate eps validation into one probe"
```

### Task 4: Power-cycle checkpoint and two-sector patch workflow

**Files:**
- Create: `eps_patch/power.py`
- Create: `eps_patch/patch.py`
- Create: retained `crc_probe.c`, `crc_intermediate.c`, `crc_verify.c`, writer sources, headers, linker files, and runtime `.bin` files
- Create: `tests/test_power.py`
- Create: `tests/test_patch.py`
- Create: retained CRC/writer source-contract and fault-model tests

**Interfaces:**
- Consumes: `load_probe_pass`, `ArtifactLayout`, existing CRC candidate and specialized-writer primitives.
- Produces: `request_power_cycle(current_state, next_state, checkpoint) -> None`, `PatchState`, and `run_patch(*, layout, payloads, templates, preflight, transport_factory, confirmation, power_cycle_checkpoint, target, new_uds) -> Path`.

- [ ] **Step 1: Write the failing power-cycle interaction test**

```python
def test_power_cycle_uses_bilingual_enter_checkpoint():
  prompts = []
  request_power_cycle("TARGET_COMMITTED", "CRC_PRECHECKED", prompts.append)
  prompt = prompts.single()
  assert "断电" in prompt
  assert "power" in prompt.lower()
  assert "UDS reset" in prompt
  assert "TARGET_COMMITTED -> CRC_PRECHECKED" in prompt
```

The callback return value is ignored: the checkpoint waits for Enter but does not require a phrase.

- [ ] **Step 2: Write failing patch discovery and fault-state tests**

Assert that `run_patch` takes a layout but no evidence paths, loads `layout.probe_report`, reconnects after each Enter checkpoint, retains exact confirmations for target and CRC writers, and records:

```python
@pytest.mark.parametrize((failure_stage, expected_result, restore_order), [
  ("before-target-arm", "FAILED", []),
  ("target-armed", "TARGET_INDETERMINATE", ["target"]),
  ("target-committed", "RECOVERY_REQUIRED", ["target"]),
  ("crc-armed", "CRC_INDETERMINATE", ["crc", "target"]),
  ("crc-committed", "RECOVERY_REQUIRED", ["crc", "target"]),
])
def test_patch_failure_persists_restore_plan(
  patch_fault_runner, failure_stage, expected_result, restore_order,
):
  state_path = patch_fault_runner.fail_at(failure_stage)
  state = json.loads(state_path.read_text())
  assert state["result"] == expected_result
  assert state["restore_order"] == restore_order
```

- [ ] **Step 3: Run patch tests and verify they fail**

Run: `python3.12 -m pytest tests/test_power.py tests/test_patch.py -v`

Expected: FAIL with missing patch/power modules.

- [ ] **Step 4: Adapt the reviewed two-sector orchestration**

Move the retained mechanics from `patch_crc` into `run_patch`. Replace `--probe-dir` and caller output arguments with `ArtifactLayout`; load semantic evidence at entry; create a UTC attempt directory; persist one canonical `state.json` after each transition; use `request_power_cycle` at all three existing complete-cycle boundaries; and reconnect/revalidate identity plus live sectors after each checkpoint. Keep exact target and CRC writer confirmations, fixed direction checks, readback verification, DCRA/software CRC agreement, and no retry.

- [ ] **Step 5: Retain and verify only patch runtime payloads**

Keep `.bin` artifacts and manifest entries for `crc_probe`, `crc_intermediate`, `crc_verify`, `write_target_candidate`, and `write_crc_candidate`. Keep their source-contract and fault-model tests. Remove obsolete `patch`, `patch_v2`, and `patch_crc` payloads.

- [ ] **Step 6: Run patch tests**

Run: `python3.12 -m pytest tests/test_power.py tests/test_patch.py tests/test_crc_workflows.py tests/test_candidate_writer_fault_model.py tests/test_candidate_writer_source_contracts.py tests/test_crc_probe_source_contracts.py tests/test_crc_intermediate_source_contracts.py -v`

Expected: PASS.

- [ ] **Step 7: Commit patch orchestration**

```bash
git add eps_patch/power.py eps_patch/patch.py payload tests
git commit -m "feat: add comma-local two-sector patch workflow"
```

### Task 5: Automatic restore planning and ordered recovery

**Files:**
- Create: `eps_patch/restore.py`
- Create: `payload/ram_echo.c`
- Create: `payload/restore_sector.c`
- Create: `payload/build/ram_echo.bin`
- Create: `payload/build/restore_sector.bin`
- Create: `tests/test_restore.py`
- Create: retained restore source-contract tests

**Interfaces:**
- Consumes: `ArtifactLayout`, `TrustedProbeEvidence`, latest patch `state.json`, RAM echo and fixed restore writer primitives.
- Produces: `RestorePlan`, `select_restore_plan(layout) -> RestorePlan`, and `run_restore(*, layout, payloads, templates, preflight, transport_factory, confirmation, power_cycle_checkpoint, target, new_uds) -> Path`.

- [ ] **Step 1: Write failing restore-plan tests**

```python
@pytest.mark.parametrize((state, expected), [
  ({"result": "TARGET_INDETERMINATE", "restore_order": ["target"]}, (0x60000,)),
  ({"result": "RECOVERY_REQUIRED", "restore_order": ["crc", "target"]}, (0xF8000, 0x60000)),
])
def test_restore_uses_persisted_minimum_safe_order(layout, state, expected):
  write_latest_patch_state(layout, state)
  assert select_restore_plan(layout).sector_bases == expected
```

Add rejection tests for no recoverable incident, PASS patch, malformed/contradictory state, missing original backup, identity mismatch, already-running restore, and indeterminate prior restore.

- [ ] **Step 2: Run restore tests and verify they fail**

Run: `python3.12 -m pytest tests/test_restore.py -v`

Expected: FAIL because restore orchestration is absent.

- [ ] **Step 3: Implement automatic incident discovery and recovery**

`select_restore_plan` scans timestamped patch attempts in descending order, selects the newest non-PASS state requiring recovery, and accepts only canonical restore orders emitted by patch. `run_restore` loads fixed probe evidence, creates a new timestamped restore attempt, validates identity and live state, specializes the restore payload from the selected original backup, requires the exact incident-bound confirmation, writes once, validates returned/readback content, and persists state. For two sectors, it restores CRC first, calls `request_power_cycle`, reconnects and revalidates, then restores target.

- [ ] **Step 4: Preserve indeterminate restore behavior**

Wrap the post-arm region so transport loss, malformed writer output, evidence-install failure, or readback uncertainty produces `INDETERMINATE`, never loops, and reports that external programming/professional recovery is required.

- [ ] **Step 5: Run restore tests and source contracts**

Run: `python3.12 -m pytest tests/test_restore.py tests/test_restore_sector_source_contracts.py tests/test_ram_echo_source_contracts.py -v`

Expected: PASS.

- [ ] **Step 6: Commit first-class restore**

```bash
git add eps_patch/restore.py payload tests/test_restore.py tests/test_restore_sector_source_contracts.py tests/test_ram_echo_source_contracts.py
git commit -m "feat: restore eps sectors from persisted incident state"
```

### Task 6: Three-command CLI

**Files:**
- Create: `eps_patch.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `run_probe`, `run_patch`, `run_restore`, `ArtifactLayout`, payload loader, preflight, and transport factory.
- Produces: `build_parser() -> argparse.ArgumentParser`, `dispatch(args, *, layout, preflight, transport_factory, confirmation, power_cycle_checkpoint) -> Path`, and `main() -> int`.

- [ ] **Step 1: Write failing exact-command tests**

```python
def test_cli_exposes_exactly_three_commands():
  parser = build_parser()
  choices = next(action for action in parser._actions if action.dest == "command").choices
  assert set(choices) == {"probe", "patch", "restore"}

@pytest.mark.parametrize("argv", [
  ["patch", "--probe-dir", "/tmp/probe"],
  ["patch", "--output", "/tmp/out"],
  ["restore", "--incident-dir", "/tmp/incident"],
])
def test_cli_rejects_user_selected_evidence_paths(argv):
  with pytest.raises(SystemExit):
    build_parser().parse_args(argv)
```

Also assert all three commands accept only optional `--serial`, dispatch to the correct workflow, use `DEFAULT_ARTIFACT_ROOT`, and reject old commands `verify`, `patch-crc`, `recover-sector`, and `verify-restore`.

- [ ] **Step 2: Run CLI tests and verify they fail**

Run: `python3.12 -m pytest tests/test_cli.py -v`

Expected: FAIL because `eps_patch.py` does not exist.

- [ ] **Step 3: Implement the thin CLI**

Build one required subparser group with only the three commands and common `--serial`. Construct `ArtifactLayout(DEFAULT_ARTIFACT_ROOT)`, `EcuTransport`, pinned payloads/templates, `input`, and `run_preflight` in dispatch. Catch known artifact, evidence, preflight, payload, transport, workflow, patch, and restore exceptions; print `ERROR: <exception message>` to stderr and return 2. Print the final report path on success and return 0.

- [ ] **Step 4: Run CLI tests**

Run: `python3.12 -m pytest tests/test_cli.py -v`

Expected: PASS.

- [ ] **Step 5: Commit the public interface**

```bash
git add eps_patch.py tests/test_cli.py
git commit -m "feat: expose probe patch and restore commands"
```

### Task 7: Documentation, offline end-to-end verification, and final cleanup

**Files:**
- Create: `README.md`
- Create: `docs/boot-crc-root-cause.md`
- Create: `tests/test_end_to_end_offline.py`
- Create: `tests/test_documentation.py`
- Modify: `.gitignore`
- Modify: `payload/build/manifest.json`

**Interfaces:**
- Consumes: completed CLI and workflows.
- Produces: operator instructions and final release-quality repository.

- [ ] **Step 1: Write failing documentation and end-to-end tests**

The documentation test must require the three exact comma commands, fixed evidence location, one-probe statement, semantic PASS rule, all power-cycle instructions, two-sector patch explanation, restore ordering, and no instructions to download/upload reports or supply a report hash.

The offline end-to-end test must execute with fakes:

```python
def test_probe_patch_restore_lifecycle_without_external_paths(tmp_path):
  layout = ArtifactLayout(tmp_path)
  bench = OfflineBench.original_8965b4512000()
  assert bench.run_probe(layout=layout) == layout.probe_report
  patch_report = bench.run_patch(layout=layout)
  assert json.loads(patch_report.read_text())["result"] == "PASS"

  incident = bench.create_crc_indeterminate_fixture(layout)
  restore_report = bench.run_restore(layout=layout)
  assert json.loads(restore_report.read_text())["result"] == "PASS"
  assert incident.restore_writes == [0xF8000, 0x60000]
```

- [ ] **Step 2: Run documentation/end-to-end tests and verify they fail**

Run: `python3.12 -m pytest tests/test_documentation.py tests/test_end_to_end_offline.py -v`

Expected: FAIL until the new documentation and complete integration contract exist.

- [ ] **Step 3: Write concise comma-only operating documentation**

Document installation/sync without caches, preflight, `probe`, semantic PASS contents, `patch`, Enter-based power cycles, precise writer confirmations, state/result meanings, `restore`, recovery order, external-programmer stop conditions, and retained scope limitations. Do not instruct the user to transfer a report to a computer or edit/hash a report.

- [ ] **Step 4: Remove all obsolete and intermediate files**

Verify the repository contains none of: legacy normal/unlock/one-sector workflows, old public phase commands, unused payload source/binaries, `.venv`, `.pytest_cache`, `__pycache__`, `.DS_Store`, compiler intermediates, runtime artifact directories, or copied incident data.

- [ ] **Step 5: Run the complete test suite**

Run: `python3.12 -m pytest -q`

Expected: all tests PASS with zero warnings or collection errors.

- [ ] **Step 6: Run explicit static hygiene checks**

Run: `rg -n "PHASE2_PE_CYCLE_REPORT_SHA256|--probe-dir|--pe-cycle-report|patch-crc|recover-sector|verify-restore" eps_patch.py eps_patch tests README.md`

Expected: no forbidden public interface or report-hash matches; any historical wording in a test fixture must be removed or explicitly scoped.

Run: `find . -path ./.git -prune -o -type f \( -name '*.o' -o -name '*.elf' -o -name '*.map' -o -name '*.disassembly' -o -name '*.symbols' -o -name '*.sections' -o -name '*.preprocessed' -o -name '.DS_Store' \) -print`

Expected: no output.

- [ ] **Step 7: Inspect repository state and retained payload manifest**

Run: `git status --short && git ls-files && python3.12 -m pytest tests/test_payload_binaries.py -v`

Expected: only intentional uncommitted documentation/test edits before the final commit; tracked files match the migration scope; payload binary checks PASS.

- [ ] **Step 8: Commit the completed migration**

```bash
git add README.md docs .gitignore payload/build/manifest.json tests
git commit -m "docs: finalize comma-local eps patch workflow"
```

- [ ] **Step 9: Final verification from clean Git state**

Run: `git status --short && python3.12 -m pytest -q`

Expected: empty Git status followed by a fully passing test suite.
