"""全量真机验证 v2：68 个 MCP 工具逐个跑，产出可审计的报告。

v1 的教训（已修）：
- `read_memory(format=)` 只认 dump/hex/base64，写 ascii 会直接报错
- `create_thread(argument=)` 是 hex **字符串**，传 int 会被 pydantic 挡掉
- 加载 32 位目标要走 `x96dbg.exe` launcher，直接给 x64dbg.exe 会 Failed to load
- `script_run` 结束会弹**模态**框，阻塞整条 bridge（已由 client 侧自愈关闭）
- 「拒绝非 call 指令」是 `skip_call` 的正确行为，不能按失败计

用法:
    C:\\Python314\\python.exe ops\\full_sweep.py
    C:\\Python314\\python.exe ops\\full_sweep.py --no-32   # 跳过 32 位段
"""
import asyncio
import json
import os
import pathlib
import re
import sys
import time

sys.path.insert(0, r"D:\toolkit\x64dbg-automate\app")

import x64dbg_automate.mcp_server as S  # noqa: E402
import x64dbg_automate.mcp_server_local as _entry  # noqa: F401,E402
from mcp.shared.memory import create_connected_server_and_client_session as cc  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
LAUNCHER = r"D:\toolkit\dbg\release\x96dbg.exe"
TARGET64 = r"C:\Windows\System32\cmd.exe"
TARGET32 = r"C:\Windows\SysWOW64\cmd.exe"
TMP = pathlib.Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
RESULTS = []
STAGE = ["init"]
BAD = re.compile(r"^(Error|ERROR)|Error: |XERROR_|unknown command|Not connected|Failed to ", re.I)


def _text(r):
    return " ".join(getattr(c, "text", "") for c in r.content if getattr(c, "text", None) is not None)


async def call(sess, name, args=None, timeout=30, expect=None, stage=None):
    args = args or {}
    t0 = time.time()
    rec = {"stage": stage or STAGE[0], "tool": name, "args": args, "status": "?", "ms": 0, "out": ""}
    try:
        r = await asyncio.wait_for(sess.call_tool(name, args), timeout)
        txt = _text(r)
        rec["ms"] = int((time.time() - t0) * 1000)
        rec["out"] = txt[:800]
        bad = bool(BAD.search(txt[:140]))
        if expect == "error":      # 拒绝 / 报错才是正确行为
            rec["status"] = "PASS" if bad else "FAIL"
        elif expect == "any":
            rec["status"] = "PASS"
        else:
            rec["status"] = "FAIL" if bad else "PASS"
    except asyncio.TimeoutError:
        rec["status"] = "TIMEOUT"
        rec["ms"] = int((time.time() - t0) * 1000)
    except Exception as e:  # noqa: BLE001
        rec["status"] = "EXC"
        rec["out"] = f"{type(e).__name__}: {e}"[:400]
        rec["ms"] = int((time.time() - t0) * 1000)
    RESULTS.append(rec)
    mark = {"PASS": ".", "FAIL": "F", "TIMEOUT": "T", "EXC": "X"}[rec["status"]]
    if rec["status"] == "PASS":
        print(f"  [{mark}] {name:<22} {rec['ms']:>5} ms  {rec['out'][:80]}")
    else:
        print(f"  [{mark}] {name:<22} {rec['ms']:>5} ms  {rec['out'][:220]}")
    return rec


def stage(n):
    STAGE[0] = n
    print(f"\n===== {n} =====")


def grab_addr(txt, pattern=r"(0x[0-9A-Fa-f]{6,})"):
    m = re.search(pattern, txt or "")
    return m.group(1) if m else None


async def main():
    skip32 = "--no-32" in sys.argv
    print(f"debugger {DBG}\nlauncher {LAUNCHER}\ntarget64 {TARGET64}\ntarget32 {TARGET32}")

    async with cc(S.mcp._mcp_server) as sess:
        # ---------- A 会话 ----------
        stage("A 会话")
        await call(sess, "list_sessions")
        await call(sess, "local_patch_info")
        await call(sess, "terminate_session", expect="any")
        await call(sess, "start_session", {"x64dbg_path": DBG, "target_exe": TARGET64})
        await call(sess, "get_debugger_status")
        await call(sess, "modules")
        await call(sess, "refresh_gui")
        await call(sess, "log_message", {"message": "sweep: hello"})
        await call(sess, "get_log", {"limit": 12})

        # ---------- B 读 ----------
        stage("B 内存/寄存器/表达式")
        await call(sess, "get_all_registers")
        r = await call(sess, "get_register", {"register": "cip"})
        r2 = await call(sess, "eval_expression", {"expression": "cip"})
        cip = grab_addr(r2["out"])
        await call(sess, "read_memory", {"address": cip or "0x0", "size": 64, "format": "hex"})
        await call(sess, "read_memory", {"address": cip or "0x0", "size": 32, "format": "dump"})
        await call(sess, "read_memory", {"address": cip or "0x0", "size": 16, "format": "base64"})
        await call(sess, "read_memory_many", {"reads": [f"{cip or '0x0'}:16"], "format": "hex"})
        await call(sess, "get_memory_map", {"limit": 5})
        await call(sess, "get_memory_map", {"state": "commit", "protect": "x", "limit": 3})
        await call(sess, "disassemble", {"address": cip or "0x0", "count": 4})
        await call(sess, "disasm_json", {"address": cip or "0x0", "count": 4})
        await call(sess, "get_label", {"address": cip or "0x0"})
        await call(sess, "get_comment", {"address": cip or "0x0"})
        await call(sess, "get_symbol", {"address": cip or "0x0"})
        await call(sess, "get_module_path", {"target": "cmd.exe"})
        await call(sess, "get_setting", {"section": "Engine", "name": "language", "type": "str"})

        # ---------- C xref / 分析 ----------
        stage("C xref / 分析")
        await call(sess, "analyse_linear", {"target": "cmd.exe"})
        await call(sess, "analyse_linear", {"target": "cmd.exe", "refresh": True})
        r = await call(sess, "eval_expression", {"expression": "mod.main()"})
        base = grab_addr(r["out"])
        await call(sess, "xref", {"target": base or "0x0"})
        await call(sess, "xref", {"target": "cmd.exe", "max_hits": 3})
        await call(sess, "analyse_range", {"target": "cmd.exe", "timeout": 25})
        await call(sess, "find_bytes", {"pattern": "CC CC", "max_hits": 3})
        await call(sess, "find_string", {"text": "cmd", "max_hits": 3})

        # ---------- D 断点 ----------
        stage("D 断点")
        await call(sess, "set_breakpoint", {"address_or_symbol": cip or "0x0", "name": "sweep1"})
        await call(sess, "list_breakpoints", {"bp_type": "software"})
        await call(sess, "toggle_breakpoint", {"address": cip or "0x0", "on": False})
        await call(sess, "toggle_breakpoint", {"address": cip or "0x0", "enable": True})
        await call(sess, "set_breakpoint", {"address_or_symbol": cip or "0x0", "bp_type": "hardware", "hardware_mode": "x"})
        await call(sess, "list_breakpoints", {"bp_type": "hardware"})
        await call(sess, "set_breakpoint", {"address_or_symbol": cip or "0x0", "bp_type": "memory", "memory_mode": "a"})
        await call(sess, "list_breakpoints", {"bp_type": "memory"})
        await call(sess, "clear_breakpoint", {"address": cip or "0x0", "bp_type": "software"})
        await call(sess, "reset_breakpoints")
        await call(sess, "list_breakpoints", {"bp_type": "software"})

        # ---------- E 执行控制 ----------
        stage("E 执行控制")
        await call(sess, "step_into", {"count": 2})
        await call(sess, "step_over", {"count": 2})
        await call(sess, "skip_instruction", {"count": 1})
        await call(sess, "get_register", {"register": "cip"})
        await call(sess, "run_to_return", {"frames": 1}, timeout=20)
        await call(sess, "go")
        await call(sess, "wait_for_event", {"event_type": "EVENT_BREAKPOINT", "timeout": 3})
        await call(sess, "pause")
        await call(sess, "get_latest_event")
        await call(sess, "get_debugger_status")

        # ---------- F 写内存 ----------
        stage("F 写内存")
        r = await call(sess, "allocate_memory", {"size": 0x1000})
        addr = grab_addr(r["out"])
        if addr:
            await call(sess, "write_memory", {"address": addr, "hex_data": "DE AD BE EF"})
            await call(sess, "read_memory", {"address": addr, "size": 4, "format": "hex"})
            await call(sess, "free_memory", {"address": addr})
        else:
            print("  [skip] write/free: allocate_memory 未返回地址")

        # ---------- G 标注 ----------
        stage("G 标注")
        await call(sess, "set_label", {"address": cip or "0x0", "text": "sweep_label"})
        await call(sess, "get_label", {"address": cip or "0x0"})
        await call(sess, "set_comment", {"address": cip or "0x0", "text": "sweep_comment"})
        await call(sess, "get_comment", {"address": cip or "0x0"})

        # ---------- H 命令 / python / 脚本 ----------
        stage("H 命令与脚本")
        await call(sess, "execute_command", {"command": "log \"sweep exec\""})
        await call(sess, "dbg_cmd_exec", {"command": "log \"sweep queue\"", "timeout": 10})
        await call(sess, "exec_command_out", {"command": "log \"sweep out\"", "log_lines": 3})
        await call(sess, "run_python", {"code": "print('sweep python ok')"})
        sc = TMP / "sweep_script.txt"
        sc.write_text('log "sweep script line"\n', encoding="utf-8")
        await call(sess, "script_load", {"path": str(sc)})
        await call(sess, "script_run", {"destline": 0}, timeout=25)
        # 弹窗已被 client 自愈关闭；这一步验证 bridge 还活着
        await call(sess, "get_debugger_status")

        # ---------- I 设置 ----------
        stage("I 设置")
        await call(sess, "set_setting", {"section": "Engine", "name": "sweep_probe", "value": "1", "type": "uint"})
        await call(sess, "get_setting", {"section": "Engine", "name": "sweep_probe", "type": "uint"})

        # ---------- J 控制台 ----------
        stage("J 控制台")
        await call(sess, "read_console", {"max_chars": 400})
        await call(sess, "send_stdin", {"text": "echo sweep", "newline": True})
        await call(sess, "read_console", {"max_chars": 400})
        await call(sess, "skip_call", {"return_value": 0}, expect="error")   # 非 call 指令：拒绝才对
        await call(sess, "skip_call", {"return_value": 0, "force": True})

        # ---------- K 线程 ----------
        stage("K 线程")
        # 符号格式：x64dbg 表达式用 module:symbol（或 module.symbol），"ntdll!xxx" 解析不了。
        # 入口用 Sleep(5000) 而不是 RtlExitUserThread：后者立刻退出，terminate_thread 就没对象可杀；
        # 5 秒窗口足够走完 pause/resume/switch/terminate。
        r = await call(sess, "create_thread", {"entry_address": "kernel32:Sleep", "argument": "8000"})
        tid = None
        m = re.search(r"TID:\s*(\d+)", r["out"])
        tid = m.group(1) if m else None
        if tid:
            # x64dbg 只有收到 CREATE_THREAD 事件后才认识这个线程；在暂停状态下刚
            # 创建的线程不在它的线程表里，pause/switch/terminate 一律 Failed。
            # 所以必须先 go 一次，让事件走完，再操作。
            await call(sess, "go")
            await call(sess, "wait_for_event", {"event_type": "EVENT_CREATE_THREAD", "timeout": 3}, expect="any")
            await call(sess, "pause")
            await call(sess, "switch_thread", {"tid": int(tid)})
            await call(sess, "pause_resume_thread", {"tid": int(tid), "action": "pause"})
            await call(sess, "pause_resume_thread", {"tid": int(tid), "action": "resume"})
            await call(sess, "terminate_thread", {"tid": int(tid)})
        else:
            print(f"  [skip] 线程工具：create_thread 未给出 TID -> {r['out'][:120]}")

        # ---------- L 挂起 / 重启 ----------
        stage("L 挂起与重启")
        await call(sess, "suspend_debuggee", {"suspend": True})
        await call(sess, "suspend_debuggee", {"suspend": False})
        await call(sess, "get_debugger_status")
        await call(sess, "restart_session", {"clean_breakpoints": True}, timeout=45)
        await call(sess, "get_debugger_status")
        await call(sess, "list_breakpoints", {"bp_type": "software"})

        # ---------- M 32 位 ----------
        if not skip32:
            stage("M 32 位（走 launcher）")
            await call(sess, "terminate_session", expect="any")
            r = await call(sess, "start_session", {"x64dbg_path": LAUNCHER, "target_exe": TARGET32}, timeout=45)
            if r["status"] == "PASS":
                await call(sess, "get_debugger_status")
                await call(sess, "get_register", {"register": "eip"})
                await call(sess, "analyse_linear", {"target": "cmd.exe"})
                await call(sess, "xref", {"target": "cmd.exe", "max_hits": 3})
                await call(sess, "read_console", {"max_chars": 200})
            await call(sess, "terminate_session", expect="any")

        # ---------- N 错误路径（无 debuggee） ----------
        stage("N 错误路径（无 debuggee）")
        await call(sess, "pause", expect="error")
        await call(sess, "get_register", {"register": "rax"}, expect="error")
        await call(sess, "read_memory", {"address": "0x1000", "size": 16, "format": "hex"}, expect="error")
        await call(sess, "xref", {"target": "0x1000"}, expect="error")
        await call(sess, "analyse_linear", {"target": "0x1000"}, expect="error")
        await call(sess, "wait_for_event", {"event_type": "EVENT_BREAKPOINT", "timeout": 1}, expect="any")

    stamp = time.strftime("%Y%m%d-%H%M")
    outp = pathlib.Path(r"D:\toolkit\x64dbg-automate\app\ops") / f"sweep-report-{stamp}.json"
    outp.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=1), encoding="utf-8")

    print("\n===== 汇总 =====")
    by = {}
    for r in RESULTS:
        by.setdefault(r["stage"], []).append(r)
    for st, rows in by.items():
        bad = [r for r in rows if r["status"] != "PASS"]
        tail = f"   << {', '.join(r['tool'] for r in bad)}" if bad else ""
        print(f"  {st:<26} {len(rows) - len(bad):>2}/{len(rows):<2}{tail}")
    bad_all = [r for r in RESULTS if r["status"] != "PASS"]
    print(f"\n  TOTAL {len(RESULTS) - len(bad_all)}/{len(RESULTS)} pass, {len(bad_all)} not-pass")
    print(f"  report -> {outp}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
