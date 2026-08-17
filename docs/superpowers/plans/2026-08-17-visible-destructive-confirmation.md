# Visible Destructive Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace invisible long `input()` prompts with one visible, flushed, exact-uppercase-`YES` confirmation for every patch and restore writer.

**Architecture:** Keep patch/restore workflow confirmation contracts unchanged. Add a CLI adapter that prints the full transaction, reads a short `YES` response, and returns the original transaction only on success; add a pre-dispatch TTY gate and a flushed power-cycle printer.

**Tech Stack:** Python 3.12, pytest, existing `eps_patch.py` CLI and injected workflow callbacks.

## Global Constraints

- Modify no V850 C source, binary, manifest, intent layout, FACI operation, sector order, or retry policy.
- Apply the adapter to target patch, CRC patch, and every restore-sector writer through the shared CLI callback.
- Accept only exact uppercase `YES`; do not strip whitespace or retry input.
- Reject non-TTY patch/restore before payload loading, preflight, transport, or state mutation.
- Use `/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python` for every test command.

---

### Task 1: Visible shared CLI confirmation

**Files:**

- Modify: `eps_patch.py:18-151`
- Modify: `tests/test_cli.py:1-165`
- Modify: `README.md` patch/restore confirmation instructions

**Interfaces:**

- Produces: `_confirm_destructive(transaction: str) -> str`, returning the original transaction only after exact `YES`.
- Produces: `_print_power_cycle(message: str) -> None`, printing with `flush=True`.
- Consumes: unchanged `run_patch(... confirmation=...)` and `run_restore(... confirmation=...)` callback interfaces.

- [x] **Step 1: Write failing behavior tests**

Add tests that call the real CLI helper and assert the operator-visible result:

```python
def test_destructive_confirmation_prints_transaction_and_accepts_only_exact_yes(
  cli_module, monkeypatch, capsys,
):
  monkeypatch.setattr("builtins.input", lambda prompt: "YES")
  transaction = "WRITE-TARGET 8965B4512000 0x60000 hashes"
  assert cli_module._confirm_destructive(transaction) == transaction
  output = capsys.readouterr().out
  assert "DESTRUCTIVE OPERATION" in output
  assert transaction in output

@pytest.mark.parametrize("answer", ("", "yes", "YES ", " YES", "NO"))
def test_destructive_confirmation_rejects_every_nonexact_answer(
  cli_module, monkeypatch, answer,
):
  monkeypatch.setattr("builtins.input", lambda prompt: answer)
  with pytest.raises(cli_module.CliError, match="exact uppercase YES"):
    cli_module._confirm_destructive("RESTORE-SECTOR transaction")
```

Add EOF coverage. Add `main()` tests for both `patch` and `restore` with a
non-TTY stdin whose `dispatch` raises if reached, proving failure occurs before
dispatch. Update the existing callback-wiring test to require
`_confirm_destructive` and `_print_power_cycle`.

- [x] **Step 2: Run RED**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_cli.py -q
```

Expected: failures because `CliError`, `_confirm_destructive`,
`_print_power_cycle`, and the non-TTY gate do not exist.

- [x] **Step 3: Implement the minimal CLI adapter and gate**

In `eps_patch.py`, add `CliError` to `_EXPECTED_ERRORS`; implement the two
helpers with explicit `flush=True`; catch EOF and raise `CliError`; reject every
answer except `YES`. In `main()`, after parsing and before `dispatch`, reject
non-TTY `patch`/`restore`, then pass the new helpers into `dispatch`.

- [x] **Step 4: Run GREEN and focused workflow regressions**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest tests/test_cli.py tests/test_patch.py tests/test_restore.py tests/test_restart_resume.py -q
```

Expected: all selected tests pass; direct workflow tests retain their injected
exact-transaction callbacks and all arm-state ordering assertions.

- [x] **Step 5: Update human instructions**

Replace instructions to paste the full transaction with exact uppercase `YES`.
State that non-interactive patch/restore is rejected and power-cycle messages
exit without waiting for Enter.

- [x] **Step 6: Verify complete repository**

Run:

```sh
/Users/kevin/Desktop/disable-secoc/sienna-b4512000-rx-secoc/.venv/bin/python -m pytest -q
git diff --check
git status --short
```

Expected: full suite passes, diff check is clean, and only the planned Python,
test, README, and plan files changed; every payload binary hash is unchanged.

- [x] **Step 7: Commit**

```sh
git add eps_patch.py tests/test_cli.py README.md docs/superpowers/plans/2026-08-17-visible-destructive-confirmation.md
git commit -m "fix: make destructive confirmations visible"
```
