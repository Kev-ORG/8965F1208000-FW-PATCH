# 8965B4512000 EPS Patch

> 面向已审查 `8965B4512000` EPS 的 comma 本机台架工具。它不是通用 ECU 刷写器；公开命令只有 `probe`、`patch`、`restore`。

## 中文操作指南

### 准备

在 comma 上使用 openpilot 的 Python 3.12 运行本仓库。不要把虚拟环境、缓存、旧运行产物或事故目录复制进仓库。`payload/build/` 中的二进制与 manifest 是已审查运行输入，不要手动替换。

运行证据固定在 `/data/eps-patch/artifacts`。每次硬件操作前，确保车辆安全停放、EPS 供电稳定，并停止 comma/openpilot/Panda 服务。脚本会检查 Python、依赖与活动服务；必须先解决所有 preflight 错误。唯一可选参数是 `--serial <Panda serial>`。

### 1. Probe：只读建立证据

```bash
python3.12 eps_patch.py probe
```

Probe 不擦除、不写入 Flash。只有所有检查通过才会原子创建：

```text
/data/eps-patch/artifacts/probe/
├── faci-pe-cycle-report.json
├── original-sector-0x60000.bin
├── original-sector-0xf8000.bin
└── recovery-metadata.json
```

PASS 代表身份、两份原始扇区、原始指令上下文、FACI `PRE → UNLOCKED → WINDOWS → CONFIGURED → RESTORED`、清理回 idle、DCRA/CRC 观察和主机验证全部通过。连接成功、终端输出或零散文件都不等于 PASS。已有 probe 目录时，命令会在任何硬件操作前拒绝运行；请保留它，它是恢复所绑定的原厂备份。

如果 probe 已完整回传但 outcome 不是 PASS，例如 `primary=3`，它仍然不会创建 `probe/` 可信证据。脚本会在终端打印 DCRA 的进入/退出 `CTL` 和 `COUT`，并原子覆盖写入仅诊断文件：`/data/eps-patch/artifacts/failures/last-probe-failure.json`。该文件一次收集身份、payload、outcome、magic、完整 DCRA 观察、五个 FACI 快照及两个扇区的地址/长度/SHA-256/CRC32 摘要；不包含扇区内容，不能用于 patch 或 restore。保留该文件和终端输出，再决定是否需要适配 DCRA 恢复行为；不要为获取额外寄存器信息而反复运行 probe。

### 2. Patch：两扇区写入

```bash
python3.12 eps_patch.py patch
```

Patch 自动读取固定 probe 证据，不接受报告、备份或目录参数。它先写目标扇区 `0x60000`，再写启动 CRC 扇区 `0xf8000`。

每个计划性断电点，脚本会持久化完成阶段、打印提示并退出。完整断开车辆/EPS 电源、等待放电、恢复稳定供电并让 comma 重启；重新 SSH 后再次运行同一条 `python3.12 eps_patch.py patch`。脚本只继续该 attempt 的下一安全阶段。成功流程在 `PROBED`、`TARGET_COMMITTED`、`CRC_COMMITTED` 后需要完整断电；UDS reset 不能代替断电。

writer 前会显示 `WRITE-TARGET` 或 `WRITE-CRC` 精确确认文本。核对地址、source、candidate、CRC 和 envelope 后逐字输入；任何差异都会在 writer arm 前停止。最终 PASS 表示独立回读精确匹配候选并通过 CRC/DCRA 验证。`TARGET_INDETERMINATE`、`CRC_INDETERMINATE`、`RECOVERY_REQUIRED` 时禁止再次 patch，改运行 restore。

### 3. Restore：恢复已记录事故

```bash
python3.12 eps_patch.py restore
```

Restore 自动发现本机可恢复 incident，只使用固定 probe 目录绑定的原厂备份。两个扇区可能受影响时固定先恢复 CRC `0xf8000`、再恢复目标 `0x60000`。每个 writer arm 前，脚本都用只读 live-read payload 重新读取两扇区，并核对 incident 范围、备份和候选状态。

Restore 的计划性断电同样是“保存阶段并退出 → 完整断电 → comma 重启 → 再运行同一条 `restore`”。每次写入前输入显示的精确 `RESTORE-SECTOR` 确认文本。若出现 `INDETERMINATE`、未知 live 状态、确认失败或 writer/readback 通信错误，停止；不要重试 patch 或 restore，应保留证据并采用外部编程器或专业恢复方式。

## 安全措施与设计

- **本机语义证据：** 在 comma 本机验证报告、身份、备份、FACI 快照、清理结果与 payload 身份；无需把文件传到电脑再传回。
- **最小接口：** 用户不能指定报告、备份、incident、扇区或产物目录；payload/template 由 manifest、大小和 SHA-256 固定。
- **一次综合 probe：** ECU payload 保留寄存器状态机、轮询、watchdog、清理和 DCRA 原始观察；SHA、软件 CRC 与回传验证由 comma 主机完成。
- **双扇区受控写入：** 固定地址、方向、intent、页数和确认；不自动 rollback、不自动重试。
- **可重启断电流程：** 计划性断电时保存状态并退出；下一次同命令只允许进入指定安全阶段。writer 已 arm 或结果不确定时绝不 resume/retry，只进入 restore。
- **Incident gate：** 每个未被绑定 PASS restore 关闭的历史 incident 都会阻止新的 patch；restore 在每次 arm 前重新 live-read 两扇区并 fail closed。

## English operating guide

This is a deliberately narrow comma-local bench workflow for the reviewed `8965B4512000` EPS. It is not a general ECU flasher; its only public commands are `probe`, `patch`, and `restore`.

### Before you start

Run the checkout on comma with the supported openpilot Python 3.12 environment. Do not copy virtual environments, caches, previous artifact directories, or incident data into the checkout. The retained binaries and manifest in `payload/build/` are reviewed runtime inputs; do not rebuild, replace, or edit them on the device.

Runtime evidence is always stored at `/data/eps-patch/artifacts`. Before every hardware command, park the vehicle safely, make EPS power stable, and stop comma/openpilot/Panda services. Preflight checks Python, dependencies, and active services; resolve every error before proceeding. The only optional argument is `--serial <Panda serial>`.

### 1. Probe

```bash
python3.12 eps_patch.py probe
```

Run `probe` once before `patch` or `restore`. Probe is read-only: it does not erase or program Flash. A semantic `PASS` atomically installs the fixed report, the original target and CRC-sector backups, and recovery metadata under the fixed artifact directory. It proves identity, original instruction context, complete FACI P/E-cycle snapshots and cleanup, DCRA/CRC observations, and host validation. A transport connection, terminal output, or partial files are not a PASS.

If fixed probe evidence already exists, the command rejects it before any preflight or transport action. Preserve it: it is the original backup set bound to recovery. If probe fails, correct the environment or the supported-EPS mismatch; do not proceed to patch and do not edit the stored evidence.

When a complete probe result has a non-PASS outcome, such as `primary=3`, the command still does not create `probe` evidence. It prints the DCRA entry/exit `CTL` and `COUT` values and atomically replaces the untrusted diagnostic at `/data/eps-patch/artifacts/failures/last-probe-failure.json`. That one file captures identity, payload, outcome, magic words, the complete DCRA observation, five FACI snapshots, and address/length/SHA-256/CRC32 summaries for both returned sectors. It contains no sector bytes and cannot authorize patch or restore. Keep the file and terminal output before deciding whether DCRA restoration needs adaptation; do not rerun probe merely to collect more register values.

### 2. Patch

```bash
python3.12 eps_patch.py patch
```

Patch reads only the fixed probe evidence; it accepts no report, backup, or artifact-directory path. It always writes the target sector (`0x60000`) first, then the CRC sector (`0xf8000`).

At every planned complete power cycle, the script persistently records the completed stage, prints the instruction, and exits. Fully remove vehicle/EPS power, allow discharge, restore stable power, wait for comma to restart, reconnect over SSH, then rerun the same `python3.12 eps_patch.py patch` command. The command resumes only the recorded next safe stage. A UDS reset is not a complete power cycle. A successful patch has planned cycles after `PROBED`, `TARGET_COMMITTED`, and `CRC_COMMITTED`.

Before each writer, inspect the displayed sector, source, candidate, CRC, and envelope values. Enter the exact displayed `WRITE-TARGET` or `WRITE-CRC` confirmation; any changed, abbreviated, or extra character stops before writer arm. Final PASS means independent readback exactly matches both candidates and validates CRC/DCRA. `TARGET_INDETERMINATE`, `CRC_INDETERMINATE`, and `RECOVERY_REQUIRED` never authorize another patch: use restore instead.

New patching is also refused while any recoverable persisted incident lacks its bound PASS restore. Restore that incident before starting a new attempt.

### 3. Restore

```bash
python3.12 eps_patch.py restore
```

Restore has no path, backup, or incident selector. It discovers the local recoverable incident and uses only the probe-bound original backups. If both sectors can be affected, it restores the CRC sector (`0xf8000`) first, then the target sector (`0x60000`). Before every writer arm, the read-only live-read payload reads both sectors again and checks the incident scope, backups, and candidate states.

Restore checkpoints use the same persist-exit-reboot-rerun model: complete the requested vehicle/EPS power cycle, wait for comma to restart, reconnect, and rerun the same `python3.12 eps_patch.py restore` command. Before a writer, enter the exact displayed `RESTORE-SECTOR` confirmation.

On unknown live state, `INDETERMINATE`, failed confirmation, or writer/readback communication failure, stop. Do not retry patch or restore. Keep the evidence and use an external programmer or professional recovery method.

## Safety and design

- **Local semantic evidence:** The comma validates the report, identity, backups, FACI snapshots, cleanup, and payload identity locally. No file needs to be moved to a computer and returned.
- **Minimal public interface:** Users cannot select reports, backups, incidents, sectors, or artifact directories. Payload templates are pinned by the manifest, size, and SHA-256.
- **One comprehensive probe:** The ECU payload retains register sequencing, bounded polling, watchdog handling, cleanup, and raw DCRA observation. The comma host verifies returned data, software checks, and artifacts.
- **Controlled two-sector writes:** Addresses, order, intent, pages, and confirmation strings are fixed. There is no automatic rollback or writer retry.
- **Restartable planned cycles:** A planned cycle saves the stage and exits. The same command after reboot may enter only the named next safe stage. An armed or uncertain writer is never resumed or retried; it is restore-only.
- **Incident gate:** Every historical incident not closed by its bound PASS restore blocks new patching. Restore performs a fresh two-sector live read before every writer arm and fails closed.

## Scope

Only the fixed reviewed `8965B4512000` old-UDS target/layout is supported. No other EPS, arbitrary firmware, manual evidence edits, sector selection, automatic retries, or road testing is supported.
