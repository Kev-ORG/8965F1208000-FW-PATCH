# Bilingual Human-Facing README Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current Chinese-first README with a complete human-facing English guide followed by a semantically matched complete Chinese guide for operating, understanding, building, and safely forking the reviewed `8965B4512000` bench workflow.

**Architecture:** Keep one root `README.md` as the operator source of truth. Extend `tests/test_documentation.py` so the public safety and ordering contract fails before the rewrite, then write the English chapters 0–4 and mirror them in Chinese chapters 0–4. Validate only documentation changes; production Python, payload sources, retained binaries, and the manifest remain byte-identical.

**Tech Stack:** GitHub-flavored Markdown, Python 3.12, pytest, Docker command examples, rsync command examples.

## Global Constraints

- English must be complete and appear before the complete Chinese version.
- Both languages must use matched numbered chapters 0 through 4 and preserve the same commands, state names, addresses, stop conditions, and recovery boundaries.
- The repository supports only the reviewed stationary-bench `8965B4512000` EPS and must never be described as a general flasher.
- Public commands remain exactly `python3.12 eps_patch.py probe`, `python3.12 eps_patch.py patch`, and `python3.12 eps_patch.py restore` with only optional `--serial <Panda serial>`.
- Runtime evidence stays at `/data/eps-patch/artifacts`; rsync targets `/data/eps-patch/app/` and must not delete or overwrite the sibling artifact tree.
- Planned power-cycle handling is checkpoint, normal process exit, complete vehicle/EPS/comma power loss and restart, reconnect SSH, then rerun the same command. There is no Enter-only continuation.
- Destructive authorization is exact uppercase `YES`; indeterminate writer outcomes are never automatically retried.
- Trigger RAM is `0xFEBF0000 / 0x1000`, FF00 uses `0xE0000 / 0x8000`, and the actual target and CRC sectors remain `0x60000` and `0xF8000`.
- The Docker image is built from `v850-cross-build/Dockerfile`; `payload/build.sh` remains the repository-owned build entry point.
- Related RH850 platforms may use a similar research method, but none of this target's addresses, credentials, binaries, constants, or recovery evidence are portable.
- Modify only `README.md`, `tests/test_documentation.py`, and this plan. Do not change production code, payload sources, `payload/build/*.bin`, or `payload/build/manifest.json`.

---

### Task 1: Lock the bilingual README contract with failing tests

**Files:**
- Modify: `tests/test_documentation.py`

**Interfaces:**
- Consumes: root `README.md` as UTF-8 text.
- Produces: executable documentation contracts for ordering, chapters, rsync safety, restart-resume behavior, cross-build commands, RH850 non-portability, and matched recovery FAQ coverage.

- [ ] **Step 1: Add an English-first and exact chapter-order test**

Add a test that reads `README.md`, locates these exact headings, and asserts monotonically increasing positions:

```python
def test_readme_is_complete_english_then_complete_chinese():
  readme = (ROOT / "README.md").read_text(encoding="utf-8")
  headings = (
    "# English",
    "## 0. Risk Warning",
    "## 1. Detailed Operating Guide",
    "## 2. Design Principles and How It Works",
    "## 3. Cross-Compilation and Porting to Other Bench ECUs",
    "## 4. FAQ",
    "# 中文",
    "## 0. 风险警告",
    "## 1. 详细操作指南",
    "## 2. 脚本设计原则和工作原理",
    "## 3. 交叉编译环境与其他台架车型移植",
    "## 4. 常见问题",
  )
  positions = [readme.index(heading) for heading in headings]
  assert positions == sorted(positions)
  assert all(readme.count(heading) == 1 for heading in headings)
```

- [ ] **Step 2: Add exact operator, build, and porting contract assertions**

Add a test that normalizes whitespace and asserts the README contains:

```python
def test_readme_documents_sync_restart_build_and_porting_contracts():
  readme = (ROOT / "README.md").read_text(encoding="utf-8")
  normalized = " ".join(readme.split())
  for required in (
    "rsync -av",
    "/data/eps-patch/app/",
    "/data/eps-patch/artifacts/",
    "reconnect SSH",
    "rerun the same command",
    "重新连接 SSH",
    "重新运行同一条命令",
    "docker build -t v850-gcc:latest v850-cross-build",
    "TOOL_PREFIX=v850-elf- ./build.sh",
    "Ubuntu 22.04",
    "binutils 2.41",
    "GCC 13.2.0",
    "RH850",
    "not portable",
    "不可移植",
  ):
    assert required in normalized
  assert "Press Enter" not in readme
  assert "按 Enter" not in readme
```

- [ ] **Step 3: Add matched FAQ recovery-coverage assertions**

Add a test that checks both language halves contain direct questions about SSH loss, `TARGET_INDETERMINATE`, `CRC_INDETERMINATE`, restore indeterminate state, external power loss, the 4 KiB envelope, `0xE0000`, Flash PASS versus functional SecOC validation, payload rebuilds, and RH850 reuse. Assert at least 22 `### Q` headings in the English half and at least 22 `### 问` headings in the Chinese half.

- [ ] **Step 4: Run the documentation tests and confirm RED**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python3.12 -m pytest tests/test_documentation.py -q
```

Expected: the existing lifecycle/root-cause tests pass, while the new heading/order, rsync/build/porting, and FAQ tests fail because the current README is Chinese-first and lacks the new complete structure.

- [ ] **Step 5: Commit the RED documentation contract**

```bash
git add tests/test_documentation.py
git commit -m "test: define bilingual readme contract"
```

### Task 2: Rewrite the complete English operator document

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the approved design spec, current CLI behavior, persisted state-machine names, retained Dockerfile, and `payload/build.sh`.
- Produces: the first half of `README.md`, beginning at `# English` and ending after English FAQ question 22.

- [ ] **Step 1: Replace the title and English chapter 0**

Write the project title, two language anchor links, `# English`, and `## 0. Risk Warning`. State the exact target and stationary-bench-only scope; stable-power, backup, and external-recovery prerequisites; interactive foreground TTY requirement; no artifact/state/payload editing; no automatic retry; and why DTCs, steering feel, silence, SSH loss, or one UDS response are not proof of Flash state.

- [ ] **Step 2: Write English chapter 1 as an end-to-end operating guide**

Include one safe rsync example whose destination is `/data/eps-patch/app/` and whose excludes cover `.git`, `.venv`, `__pycache__`, `.pytest_cache`, tests, and `docs/superpowers`. Explicitly warn not to use `--delete` against `/data/eps-patch/` and not to copy `/data/eps-patch/artifacts/` into the app tree.

Document preflight checks and the exact probe, patch, and restore commands. Explain probe PASS files and the untrusted failure diagnostic. Describe every patch checkpoint, one payload per invocation, normal exit, complete power cycle, comma restart, SSH reconnection, and rerunning the same command. Explain exact `YES`, the result/action matrix, the narrow audited CRC reconciliation, restore discovery/live-read/writer ordering, external recovery stops, and evidence preservation.

- [ ] **Step 3: Write English chapter 2 with implementation-aligned internals**

Explain semantic evidence, identity and immutable-history bindings, 4 KiB envelopes, the FF00 trigger-versus-actual-sector distinction, ECU-local 32 KiB read-modify-write, single-connection payload execution, persisted precheck/writer separation, FACI checks/cleanup, `0x664E6: 0x31 -> 0x10`, `0xFFDEC`, CRC/DCRA, atomic artifacts, incident gates, and the distinction between Flash PASS and later stationary functional validation.

- [ ] **Step 4: Write English chapter 3 with exact cross-build commands and fork checklist**

Include exactly:

```bash
docker build -t v850-gcc:latest v850-cross-build

docker run --rm \
  -v "$PWD/payload:/src" \
  -w /src \
  v850-gcc:latest \
  sh -c 'TOOL_PREFIX=v850-elf- ./build.sh'
```

Describe the Ubuntu 22.04/binutils 2.41/GCC 13.2.0 toolchain and the required source binding, payload size, SHA-256, envelope pin, disassembly, forbidden-address, focused-test, and full-test reviews. Add the complete RH850 fork checklist and a prominent statement that build compatibility does not make target-specific values portable.

- [ ] **Step 5: Write English chapter 4 with 22 direct operator Q&As**

Use `### Q1.` through `### Q22.`. Cover every question listed in the design spec, with direct state-machine-consistent answers. Never infer writer success from DTCs or communication behavior, never present a general retry, never instruct state editing, and route unknown/partial or repeated indeterminate outcomes to evidence preservation and external/professional recovery.

- [ ] **Step 6: Run documentation tests to measure remaining bilingual failures**

Run the documentation test command from Task 1. Expected: existing English lifecycle phrases and English-specific contracts pass; Chinese completeness and final matched-order/FAQ requirements remain failing until Task 3.

### Task 3: Add the complete matched Chinese operator document

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the completed English chapters from Task 2.
- Produces: a complete semantically matched Chinese translation beginning at `# 中文`, with chapters 0–4 and 22 recovery Q&As.

- [ ] **Step 1: Write Chinese chapters 0 and 1**

Mirror every risk boundary and every operational instruction from English. Preserve commands, paths, states, addresses, exact uppercase `YES`, one-payload-per-invocation behavior, complete power-cycle/re-SSH/rerun behavior, result/action decisions, CRC reconciliation limits, restore order, and evidence-preservation rules.

- [ ] **Step 2: Write Chinese chapters 2 and 3**

Mirror the full design explanation and cross-build tutorial. Preserve technical names and values exactly, and explicitly say RH850 research steps are likely similar while the target-specific addresses, SecurityAccess data, binaries, CRC constants, Flash geometry, manifests, and recovery evidence are not portable.

- [ ] **Step 3: Write Chinese chapter 4 with 22 matched Q&As**

Use `### 问1：` through `### 问22：` in the same order as English Q1–Q22. Answers must lead to the same stop, resume, restore, or external-recovery decision as the corresponding English answer.

- [ ] **Step 4: Run documentation tests and confirm GREEN**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python3.12 -m pytest tests/test_documentation.py -q
```

Expected: all documentation tests pass.

- [ ] **Step 5: Commit the bilingual README**

```bash
git add README.md
git commit -m "docs: rewrite complete bilingual operator guide"
```

### Task 4: Verify documentation fidelity and repository integrity

**Files:**
- Verify: `README.md`
- Verify: `tests/test_documentation.py`
- Verify unchanged: `eps_patch.py`, `eps_patch/`, `payload/`, `payload/build/manifest.json`, `payload/build/*.bin`

**Interfaces:**
- Consumes: all documentation changes from Tasks 1–3.
- Produces: test evidence and a clean documentation-only Git diff suitable for local integration.

- [ ] **Step 1: Compare both language halves mechanically**

Confirm one occurrence of every numbered heading, English-first order, exactly 22 English Q headings, exactly 22 Chinese question headings, and exact equality of the three command occurrence counts, four key addresses, five patch checkpoint arrows, and critical stop-state names across both halves.

- [ ] **Step 2: Scan for unsafe or stale guidance**

Use `rg` to reject `Press Enter`, `按 Enter`, report download/upload/hash-lock instructions, automatic/general retry language, state editing instructions, 32 KiB RequestDownload claims, and any statement that `0xE0000` is the actual written sector.

- [ ] **Step 3: Verify the diff is documentation-only**

Run:

```bash
git diff --name-only da15a61..HEAD
git diff --check
git status --short
```

Expected changed paths are only `README.md`, `tests/test_documentation.py`, and this plan document; whitespace check is clean.

- [ ] **Step 4: Run focused and full verification with the mandated Python 3.12**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python3.12 -m pytest tests/test_documentation.py -q
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python3.12 -m pytest -q
```

Expected: documentation tests and the full repository suite pass with zero failures.

- [ ] **Step 5: Review the final README against the approved design spec**

Walk every requirement in `docs/superpowers/specs/2026-08-17-bilingual-human-readme-design.md` and point it to a README section. Fix any missing, asymmetric, stale, or implementation-inconsistent instruction before completion.

- [ ] **Step 6: Commit verification-only corrections if needed**

If review finds documentation/test corrections, stage only `README.md` and `tests/test_documentation.py` and commit:

```bash
git add README.md tests/test_documentation.py
git commit -m "docs: align bilingual safety guidance"
```

If no corrections are needed, do not create an empty commit.
