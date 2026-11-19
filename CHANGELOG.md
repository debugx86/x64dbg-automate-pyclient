# Changelog

`x64dbg-automate` 本地 fork（`D:\toolkit\x64dbg-automate\app`，分支即版本号）。
包版本 `<上游>+local.N` 由三处同步：`x64dbg_automate/local_ext.py::PATCH`、
`x64dbg_automate/mcp_server.py::_XAUTO_MCP_PATCH`、`pyproject.toml::version`
—— `ops/verify.py` §0 会断言三处与已安装 dist 元数据一致。
local.9 及更早的历史见 `README-LOCAL.md`。

## 0.9.2+local.20 — 2026-11-20（定版）

pause() 反反调试兜底的三处缺陷修复 + `script_run(expect=)` 的两处判据修复。
全部实测：`ops/verify.py` 10 节 EXIT=0、`ops/full_sweep.py` 104/104、
`ops/local20_regression.py` 三项全通过。

- **fix(pause): int3 页兜底在全新会话里必然失败**。x64dbg 在目标 running 时只把软件断点
  记进表，**不把 0xCC 写进内存**（落字节发生在下一次 pause 时），而 `createthread` 起的
  线程立刻就跑过我们写的 `C3`(ret) 退出了。表现：`wait_until_stopped` 超时、state 仍
  running；`ops/pause_matrix.py` 里 C 行显示 True 只是因为它排在原生 pause 之后。
  现在 `set_breakpoint()` 之后自己补写 `b"\xCC"`。复测：全新会话第一次调用即停住（154 ms）。
- **fix(pause): 兜底停住后寄存器上下文可读**。原实现先 `killthread` 杀掉注入线程，导致
  活动线程失效，`pause()` 返回 True 而之后 `cip` 恒为 0（作者矩阵里 `C_int3_page ...
  cip=0x0` 就是这个）。现在先 `switchthread` 回主线程再清理，并回读 `cip` 校验。
- **fix(pause): `_pause_page` 跨会话失效**。`start_session` / `restart_session` /
  `terminate_session` 三处清零缓存，另外 `_valid_pause_page()` 会用 `memmap()` 校验缓存页
  是否还在当前地址空间里，避免把线程指向已释放地址。
- **feat(mcp): `pause(fast=, force=)`**。库层 `force=True` 已经会改目标（写 PEB 字节、
  分配页、注入线程），但 MCP 层以前没法关。现在 `force=False` = 纯 x64dbg pause，不碰目标。
  实测：`PEB+2=00` 时 `pause(force=false)` 返回 `Failed to pause.` 且字节仍是 `00`。
- **fix(script_run): 归因文案按证据分三类**。原来无论哪种失败都写"未知命令还不报错"，
  把「脚本正常跑完但本身不打 log」（`lblset`/`cmtset` 成功时不产生日志行）也判成未知命令。
  现在：日志里有错误行就抄那一行；一行日志都没有就两种可能并列说明；有日志没到哨兵就报
  最后一条。
- **fix(script_run): 哨兵只在本次运行新增的日志里找**。以前整段扫描会话日志，同一个脚本
  连跑两次时第二次的 `expect` 会被上一轮留下的旧行判成"已出现"（假命中）。现在先量日志
  基数 `base`，只扫 `get_log(base)` 之后的行。回归：`ops/verify.py` §10 的 `_StaleFake`
  + `ops/local20_regression.py` T2 实机双跑。
- **docs: trace_over / trace_into 的发起状态约束（首次实测）**。必须"停在代码里"才能 trace：
  系统断点处 `trace_over(break_condition="0", max_steps=20)` 201 ms 返回 True；
  running 态发起立即 False；**停在内核等待点发起会等满 wait_timeout 才 False，
  并把会话状态推成 running**（原先挂在"仍未验证"清单上，现在闭环）。

### ci（同版跟进提交，不改运行时代码）

- **macOS 腿从每次 push 的矩阵里挪走**。local.19 与 local.20 两次 push 的
  `test / macos-latest / py3.13` 都在排队整整 15 分钟后被 `cancelled` —— `runner_name` 为空、
  `steps` 为空，即**从未拿到 runner**；而 local.18 同一条腿排队约 10 分钟后拿到 runner、36 s 全绿。
  结论：私有仓库免费套餐下 hosted macOS 是稀缺资源，放在 per-push 矩阵里只会随机把闸门染红。
  现在 push/PR 闸门 = ubuntu×3 + windows×3；macOS 变成独立作业 `macos`，只在
  **定时（每周一 03:30 UTC）或 `gh workflow run ci.yml --ref <分支>` 手动**时跑，
  `timeout-minutes: 25` 且 `continue-on-error: true`（诊断用，不阻塞 `ci` 闸门；`ci.needs` 仍只依赖 `test`）。

## 0.9.2+local.19 — 2026-11-20

- feat(pause): 三级兜底 —— 检测 `PEB.BeingDebugged==0` 时跳过两次注定失败的 pause；
  临时写回 `01` 借 x64dbg 自己的 break-in 停住（`finally` 恢复原值）；再不行注入线程到
  已登记断点的页。C3 的归因由"ScyllaHide 吞断点异常"更正为
  `ntdll!DbgUiRemoteBreakin` 的两道前置检查（反汇编实测）。
- fix(pause): 旧失败分支引用了未定义的 `logger`，真失败时抛 `NameError`。

## 0.9.2+local.18 — 2026-11-19

- feat(script_run): `expect=` 哨兵判定，把"半截中止的脚本"从静默成功变成显式 FAILED；
  不传 `expect` 时行为与旧版一致，工具数仍 68。
- docs: 脚本引擎白名单与中止语义（`setlabel`/`setcomment`/`setreg` 不是命令，
  正解 `lblset` / `cmtset` / `rax=0x..`，普通命令走 `scriptcmd` 转发）。
- ops: `script_probe*.py` / `expect_probe.py` 五轮取证。

## 0.9.2+local.17 — 2026-11-19

- fix(client): `script_run` 结束时 x64dbg 弹 Qt 模态框会毒死整条 bridge。现在
  `dismiss_debugger_dialogs_soon(4.0)` 轮询关窗，且任何请求超时都「关窗 → 重建 REQ
  socket → 重试一次」。注意类名是 `Qt5QWindowIcon`，只匹配 `#32770` 一个都关不掉。

## 0.9.2+local.16 — 2026-11-19

- feat(plugin+client): 插件内线性 xref 引擎（`analyse_linear`）：不碰 GUI 选区、真指令边界、
  一次 IPC 出全模块边；421 KB 模块 184 ms，缓存后 7 ms；旧插件自动回落慢路径。
- fix: `find_bytes` 按 64 MB 窗口分段不再截断；`read_console` 全角字符不再错位；
  新增 `suspend_debuggee`（`NtSuspendProcess`）与 `reset_breakpoints`。

## 0.9.2+local.15 及更早

见 git log（`git tag` 列表 v0.9.2-local.1..15）与 `README-LOCAL.md`。
