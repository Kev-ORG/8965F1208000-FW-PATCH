# 8965B4512000 EPS Patch

> 面向已审查 `8965B4512000` EPS 的 comma 本机台架工具。它不是通用 ECU 刷写器；公开命令只有 `probe`、`patch`、`restore`。

## 中文操作指南

### 准备

在 comma 上使用 openpilot 的 Python 3.12 运行本仓库。不要把虚拟环境、缓存、旧运行产物或事故目录复制进仓库。`payload/build/` 中的二进制与 manifest 是已审查运行输入，不要手动替换。

运行证据固定在 `/data/eps-patch/artifacts`。每次硬件操作前，确保车辆安全停放、EPS 供电稳定，并停止 comma/openpilot/Panda 服务。脚本会检查 Python、依赖与活动服务；必须先解决所有 preflight 错误。唯一可选参数是 `--serial <Panda serial>`。

`patch` 和 `restore` 必须在可交互的 SSH 终端中运行。管道、后台任务或没有 TTY 的远程执行会在连接 Panda 之前被拒绝；不要用自动输入绕过人工确认。

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

每次 payload 下载都严格是 `0xFEBF0000` 的 `0x1000`（4 KiB）加密 envelope。32 KiB 扇区绝不会由主机上传到 SRAM：写入前 writer 在 ECU 内从已验证的 Flash 扇区复制到 SRAM，只修改固定的指令字或 CRC 调整字，并在擦写前校验本地生成候选的 CRC。CRC 预检也直接读取 Flash 并验证软件 CRC 与 DCRA；它不再把“主机上传数据的 SRAM 回显”当作 Flash 真实性证明。

一次 `patch` 命令最多下载并执行一个 ECU payload，绝不会在一个已经驻留 RAM payload 的 UDS 会话后立即打开第二个 UDS 会话。每个 payload 之后，脚本会先持久化完成阶段、打印提示并正常退出。完整断开车辆/EPS 电源、等待放电、恢复稳定供电并让 comma 重启；重新 SSH 后再次运行同一条 `python3.12 eps_patch.py patch`。脚本只继续该 attempt 的下一安全阶段，绝不会自动重试。

成功流程共有五个计划性断电点：`PROBED → TARGET_PRECHECKED`、`TARGET_PRECHECKED → TARGET_ARMED`、`TARGET_COMMITTED → CRC_PRECHECKED`、`CRC_PRECHECKED → CRC_ARMED`、`CRC_COMMITTED → VERIFY_PENDING`。其中两个 `*_PRECHECKED` 阶段只完成只读 CRC/DCRA 检查，没有 arm writer；下一次重新运行才会显示精确确认并执行对应 writer。UDS reset 不能代替完整断电。

writer 前会先单独显示完整的 `WRITE-TARGET` 或 `WRITE-CRC` 交易摘要，然后明确显示 `输入大写 YES 继续 / Type YES to continue:`。核对地址、source、candidate、CRC 和 envelope 后，只输入精确的大写 `YES` 并回车；小写、空行、前后空格或其他文本都会在 writer arm 前停止。最终 PASS 表示独立回读精确匹配候选并通过 CRC/DCRA 验证。`TARGET_INDETERMINATE` 和 `RECOVERY_REQUIRED` 禁止再次 patch，改运行 restore。`CRC_INDETERMINATE` 只允许下面这一条受限的只读判定路径。

#### CRC writer 回传不确定时

如果 CRC writer 已 arm，但主机没有收到完整、有效的六阶段状态和扇区回读，脚本会记录 `CRC_INDETERMINATE`。终端出现 `unknown frame type 0x03` 不能证明 CRC 写入成功或失败：`0x03` 是 ISO-TP 单帧长度，UDS `7F 31 78` 表示 RoutineControl Response Pending。新版主机解析会忽略该 Pending，而不要求 CAN padding 全为零；其他 NRC 或未知帧会输出完整 raw hex。

安装新版脚本后，完成车辆/EPS 与 comma 的完整断电重启，重新 SSH，再运行一次：

```bash
python3.12 eps_patch.py patch
```

这次命令只运行已审查的只读 `live_read`，完整读取 target 与 CRC 两个 32 KiB 扇区，逐字节与固定 source/candidate 比较；它不会进入 FACI P/E，也不会显示 `YES`：

- 输出/状态为 `CRC_PRECHECKED`：target 完整等于候选、CRC 完整等于原始 source。按提示完整断电重启，再运行 `patch`；核对 `WRITE-CRC` 后输入大写 `YES`，只允许这一次人工重写。
- 输出/状态为 `CRC_COMMITTED`：target 和 CRC 都已完整等于候选。脚本不会再次写 CRC；按提示完整断电重启，再运行 `patch` 完成最终只读 CRC/DCRA 验证。
- 报告 partial/unknown、身份不符或 live-read 不完整：不要再次运行 `patch`，运行 `restore`。原 `CRC_INDETERMINATE` state 保持不变。

若那一次人工 CRC 重写仍变成 `CRC_INDETERMINATE`，以后所有 `patch` 都会在 preflight、Panda 连接和确认之前拒绝；只能进入 restore。车辆故障码或转向状态不能代替完整扇区回读。

### 3. Restore：恢复已记录事故

```bash
python3.12 eps_patch.py restore
```

Restore 自动发现本机可恢复 incident，只使用固定 probe 目录绑定的原厂备份。两个扇区可能受影响时固定先恢复 CRC `0xf8000`、再恢复目标 `0x60000`。每个 writer arm 前，脚本都用只读 live-read payload 重新读取两扇区，并核对 incident 范围、备份和候选状态。

Restore 的计划性断电同样是“保存阶段并退出 → 完整断电 → comma 重启 → 再运行同一条 `restore`”。一次命令最多执行一个 ECU payload：一次只读 live-read 与下一次 writer 永远分开，两个扇区之间也会保存阶段并退出。每次写入前先核对完整的 `RESTORE-SECTOR` 交易摘要，再在独立提示处输入精确的大写 `YES`。若出现 `INDETERMINATE`、未知 live 状态、确认失败或 writer/readback 通信错误，停止；不要重试 patch 或 restore，应保留证据并采用外部编程器或专业恢复方式。

## 安全措施与设计

- **本机语义证据：** 在 comma 本机验证报告、身份、备份、FACI 快照、清理结果与 payload 身份；无需把文件传到电脑再传回。
- **最小接口：** 用户不能指定报告、备份、incident、扇区或产物目录；payload/template 由 manifest、大小和 SHA-256 固定。
- **一次综合 probe：** ECU payload 保留寄存器状态机、轮询、watchdog、清理和 DCRA 原始观察；SHA、软件 CRC 与回传验证由 comma 主机完成。
- **双扇区受控写入：** 固定地址、方向、intent、页数和确认；不自动 rollback、不自动重试。
- **可重启断电流程：** 计划性断电时保存状态并退出；下一次同命令只允许进入指定安全阶段。唯一例外是一个尚未重试的 `CRC_INDETERMINATE` 可先执行一次只读双扇区判定；只有精确 source 才允许一次新的人工确认 writer，精确 candidate 跳过 writer，其他状态只进入 restore。
- **Incident gate：** 每个未被绑定 PASS restore 关闭的历史 incident 都会阻止新的 patch；restore 在每次 arm 前重新 live-read 两扇区并 fail closed。

## English operating guide

This is a deliberately narrow comma-local bench workflow for the reviewed `8965B4512000` EPS. It is not a general ECU flasher; its only public commands are `probe`, `patch`, and `restore`.

### Before you start

Run the checkout on comma with the supported openpilot Python 3.12 environment. Do not copy virtual environments, caches, previous artifact directories, or incident data into the checkout. The retained binaries and manifest in `payload/build/` are reviewed runtime inputs; do not rebuild, replace, or edit them on the device.

Runtime evidence is always stored at `/data/eps-patch/artifacts`. Before every hardware command, park the vehicle safely, make EPS power stable, and stop comma/openpilot/Panda services. Preflight checks Python, dependencies, and active services; resolve every error before proceeding. The only optional argument is `--serial <Panda serial>`.

Run `patch` and `restore` only from an interactive SSH terminal. Piped, background, or otherwise non-TTY execution is rejected before any Panda connection; do not automate the human authorization input.

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

Every payload download is exactly one encrypted `0x1000` (4 KiB) envelope at `0xFEBF0000`. The 32 KiB sector is never uploaded from the host to SRAM: before erasing, the writer copies the verified live Flash sector into ECU SRAM, changes only the fixed instruction word or CRC adjustment word, and checks the locally derived candidate CRC. CRC precheck also reads Flash directly and verifies both software CRC and DCRA; a host-uploaded SRAM echo is not treated as proof of live Flash.

Each `patch` invocation downloads and executes at most one ECU payload. It never follows a resident RAM payload by immediately opening a second UDS session. After that payload, the script persistently records the completed stage, prints the instruction, and exits successfully. Fully remove vehicle/EPS power, allow discharge, restore stable power, wait for comma to restart, reconnect over SSH, then rerun the same `python3.12 eps_patch.py patch` command. The command resumes only the recorded next safe stage and never retries automatically.

A successful patch has five planned complete-power-cycle boundaries: `PROBED → TARGET_PRECHECKED`, `TARGET_PRECHECKED → TARGET_ARMED`, `TARGET_COMMITTED → CRC_PRECHECKED`, `CRC_PRECHECKED → CRC_ARMED`, and `CRC_COMMITTED → VERIFY_PENDING`. The two `*_PRECHECKED` stages perform only read-only CRC/DCRA checks and do not arm a writer; the following invocation displays the exact confirmation and runs that writer. A UDS reset is not a complete power cycle.

Before each writer, the script displays the complete `WRITE-TARGET` or `WRITE-CRC` transaction on its own, followed by `Type YES to continue:`. Inspect the sector, source, candidate, CRC, and envelope values, then type exactly uppercase `YES` and press Enter. Lowercase, an empty answer, surrounding whitespace, or any other text stops before writer arm. Final PASS means independent readback exactly matches both candidates and validates CRC/DCRA. `TARGET_INDETERMINATE` and `RECOVERY_REQUIRED` never authorize another patch: use restore instead. `CRC_INDETERMINATE` permits only the constrained read-only reconciliation below.

#### When the CRC writer response is indeterminate

If the CRC writer was armed but the host did not receive a complete valid six-stage status and sector readback, the script records `CRC_INDETERMINATE`. An `unknown frame type 0x03` message does not prove whether CRC programming happened: `0x03` is the ISO-TP single-frame length, and UDS `7F 31 78` is RoutineControl Response Pending. The corrected host parser ignores that Pending response regardless of CAN padding; other NRCs and unknown frames retain their complete raw hex.

After installing the corrected code, fully power-cycle the vehicle/EPS and comma, reconnect SSH, and run once:

```bash
python3.12 eps_patch.py patch
```

This invocation runs only the reviewed read-only `live_read` payload. It reads both complete 32 KiB sectors and compares every byte with the fixed source and candidate. It never enters FACI P/E and never prompts for `YES`:

- `CRC_PRECHECKED`: target is the complete candidate and CRC is the complete source. Perform the requested complete power cycle, rerun `patch`, inspect `WRITE-CRC`, and type exact uppercase `YES`. This is the one permitted manual rewrite.
- `CRC_COMMITTED`: both target and CRC are already complete candidates. No CRC writer runs; perform the requested complete power cycle and rerun `patch` for final read-only CRC/DCRA verification.
- partial/unknown, identity mismatch, or incomplete live-read: do not run `patch` again. Run `restore`; the original `CRC_INDETERMINATE` state remains unchanged.

If the one manual CRC rewrite is also `CRC_INDETERMINATE`, every later `patch` is rejected before preflight, Panda connection, or confirmation. Only restore remains. Vehicle DTCs or steering state are not substitutes for complete sector readback.

New patching is also refused while any recoverable persisted incident lacks its bound PASS restore. Restore that incident before starting a new attempt.

### 3. Restore

```bash
python3.12 eps_patch.py restore
```

Restore has no path, backup, or incident selector. It discovers the local recoverable incident and uses only the probe-bound original backups. If both sectors can be affected, it restores the CRC sector (`0xf8000`) first, then the target sector (`0x60000`). Before every writer arm, the read-only live-read payload reads both sectors again and checks the incident scope, backups, and candidate states.

Restore checkpoints use the same persist-exit-reboot-rerun model: complete the requested vehicle/EPS power cycle, wait for comma to restart, reconnect, and rerun the same `python3.12 eps_patch.py restore` command. Each invocation executes at most one ECU payload: a read-only live-read and its following writer are always separate invocations, and the script also exits between sectors. Before every writer, inspect the complete `RESTORE-SECTOR` transaction, then type exactly uppercase `YES` at the separate prompt.

On unknown live state, `INDETERMINATE`, failed confirmation, or writer/readback communication failure, stop. Do not retry patch or restore. Keep the evidence and use an external programmer or professional recovery method.

## Safety and design

- **Local semantic evidence:** The comma validates the report, identity, backups, FACI snapshots, cleanup, and payload identity locally. No file needs to be moved to a computer and returned.
- **Minimal public interface:** Users cannot select reports, backups, incidents, sectors, or artifact directories. Payload templates are pinned by the manifest, size, and SHA-256.
- **One comprehensive probe:** The ECU payload retains register sequencing, bounded polling, watchdog handling, cleanup, and raw DCRA observation. The comma host verifies returned data, software checks, and artifacts.
- **Controlled two-sector writes:** Addresses, order, intent, pages, and confirmation strings are fixed. There is no automatic rollback or writer retry.
- **Restartable planned cycles:** A planned cycle saves the stage and exits. The same command after reboot may enter only the named next safe stage. The sole exception is one not-yet-retried `CRC_INDETERMINATE`, which may run one read-only two-sector classification: exact source permits one newly confirmed writer, exact candidate skips the writer, and every other state is restore-only.
- **Incident gate:** Every historical incident not closed by its bound PASS restore blocks new patching. Restore performs a fresh two-sector live read before every writer arm and fails closed.

## Scope

Only the fixed reviewed `8965B4512000` old-UDS target/layout is supported. No other EPS, arbitrary firmware, manual evidence edits, sector selection, automatic retries, or road testing is supported.
