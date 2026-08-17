# V850 Cross-Build Dockerfile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the known V850 cross-toolchain Dockerfile under a dedicated project directory without importing or changing any build scripts or payload artifacts.

**Architecture:** A single `v850-cross-build/Dockerfile` is copied byte-for-byte from the reviewed `secoc-icanhack/shellcode/Dockerfile`. The container supplies the `v850-elf-*` tools already consumed by `payload/build.sh`; no wrapper, generated file, or runtime integration is added.

**Tech Stack:** Docker, Ubuntu 22.04, GNU binutils 2.41, GCC 13.2.0, V850 ELF cross-toolchain

## Global Constraints

- `v850-cross-build` contains exactly one file named `Dockerfile`.
- The Dockerfile is byte-for-byte identical to `/Users/kevin/Desktop/disable-secoc/secoc-icanhack/shellcode/Dockerfile`.
- Do not copy `build.sh`, `build_docker.sh`, `.gitignore`, `main.c`, or generated artifacts.
- Do not modify `payload/build.sh`, retained payload binaries, or `payload/build/manifest.json`.
- Do not build the image or perform hardware/network operations.

---

### Task 1: Add the isolated V850 toolchain container definition

**Files:**
- Create: `v850-cross-build/Dockerfile`
- Verify unchanged: `payload/build.sh`
- Verify unchanged: `payload/build/manifest.json`

**Interfaces:**
- Consumes: `/Users/kevin/Desktop/disable-secoc/secoc-icanhack/shellcode/Dockerfile`
- Produces: a Docker image definition placing `v850-elf-gcc`, `v850-elf-ld`, and `v850-elf-objcopy` on `PATH`

- [ ] **Step 1: Record existing build-interface hashes**

Run:

```bash
shasum -a 256 payload/build.sh payload/build/manifest.json
```

Expected: two SHA-256 records retained for the post-copy comparison.

- [ ] **Step 2: Verify the destination is absent**

Run:

```bash
test -f v850-cross-build/Dockerfile
```

Expected: nonzero exit because the file does not exist yet.

- [ ] **Step 3: Create the exact Dockerfile**

Copy the source Dockerfile byte-for-byte to `v850-cross-build/Dockerfile`. The file must retain Ubuntu 22.04, target `v850-elf`, binutils branch `binutils-2_41-release`, GCC branch `releases/gcc-13.2.0`, the freestanding C-only configuration, and `/opt/gcc-v850-elf-master/bin` on `PATH`. Use `apply_patch`; do not copy any neighboring source file.

- [ ] **Step 4: Verify equality and isolation**

Run:

```bash
cmp -s /Users/kevin/Desktop/disable-secoc/secoc-icanhack/shellcode/Dockerfile v850-cross-build/Dockerfile
find v850-cross-build -mindepth 1 -maxdepth 1 -type f -print
find v850-cross-build -mindepth 1 -maxdepth 1 ! -type f -print
```

Expected: `cmp` exits zero, the first `find` prints only `v850-cross-build/Dockerfile`, and the second prints nothing.

- [ ] **Step 5: Verify the existing build interface did not change**

Repeat Step 1 and require the same two hashes.

- [ ] **Step 6: Run repository verification**

Run:

```bash
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python3.12 -m pytest -q tests/test_repository_hygiene.py tests/test_payload_binaries.py tests/test_candidate_writer_source_contracts.py tests/test_restore_sector_source_contracts.py
git diff --check
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python3.12 -m pytest -q
```

Expected: focused and complete suites pass; `git diff --check` is silent.

- [ ] **Step 7: Commit**

```bash
git add v850-cross-build/Dockerfile docs/superpowers/plans/2026-08-17-v850-cross-build-dockerfile.md
git commit -m "build: add v850 cross-toolchain container"
```

