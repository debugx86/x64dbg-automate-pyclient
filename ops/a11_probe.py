"""A11 / A12 真机探针（local.13 遗留的两条待判定项）。

A11: `init` / `rerun` / `rein` 走 DbgCmdExec（真命令队列 + 哨兵）到底生不生效。
     判据不是「返回成功」，而是 debuggee PID 变了、状态回到系统断点、RPC 仍活。
A12: `SetBreakpointFastResume addr, 1` 返回成功后断点是否真的不暂停。

用法:
    C:\\Python314\\python.exe ops\\a11_probe.py [target.exe]

环境变量 X64DBG_EXE 可覆盖调试器路径（默认 D:\\toolkit\\dbg\\release\\x64\\x64dbg.exe）。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = os.environ.get("X64DBG_EXE", r"D:\toolkit\dbg\release\x64\x64dbg.exe")
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"D:\tmp\Freedom.exe"


def snap(c, tag):
    """Safely read the three state bits that prove the session survived."""
    def safe(fn):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - a dead RPC is a result, not a crash
            return f"<{type(e).__name__}: {e}>"

    pid = safe(c.debugee_pid)
    running = safe(c.is_running)
    debugging = safe(c.is_debugging)
    print(f"  [{tag}] pid={pid} running={running} debugging={debugging}")
    return pid, running, debugging


def log_tail(c, n=10):
    try:
        total = c.get_log(0, 1, "")[0]
        if not total:
            print("   log| <empty>")
            return
        _, tail, _, _ = c.get_log(max(0, total - n), n, "")
        for line in tail:
            print("   log|", line.replace("\n", " ")[:170])
    except Exception as e:  # noqa: BLE001
        print(f"   log| <{type(e).__name__}: {e}>")


def probe_rerun(c):
    print("\n=== A11: rerun via DbgCmdExec ===")
    pid0, _, _ = snap(c, "before")
    queued, executed, ms = c.dbg_cmd_exec("rerun", 20)
    print(f"  rerun -> queued={queued} executed={executed} elapsed={ms}ms")
    time.sleep(2.0)
    pid1, running1, debugging1 = snap(c, "after")

    ok = False
    if isinstance(pid1, int) and isinstance(pid0, int):
        ok = pid1 != pid0 and debugging1 is True
    elif isinstance(pid1, int) and pid0 != pid1:
        ok = True
    print(f"  VERDICT: {'PID changed + session alive' if ok else 'rerun did not restart the debuggee'}")
    log_tail(c)
    return ok


def probe_init(c):
    """`init` is the real command (rerun does not exist); it wants an argument."""
    print("\n=== A11: init <path> via DbgCmdExec (after stop) ===")
    try:
        c.cmd_sync("stop")
    except Exception as e:  # noqa: BLE001
        print(f"  stop raised: {e}")
    time.sleep(1.0)
    snap(c, "stopped")

    quoted = TARGET.replace("\\", "\\\\")
    queued, executed, ms = c.dbg_cmd_exec(f'init "{TARGET}"', 25)
    print(f"  init \"{TARGET}\" -> queued={queued} executed={executed} elapsed={ms}ms")
    time.sleep(2.5)
    pid, running, debugging = snap(c, "after-init")
    print(f"  VERDICT: {'debuggee back' if isinstance(pid, int) else 'init left no debuggee'}")
    log_tail(c)
    return isinstance(pid, int)


def _find_entry(c):
    """mod.entry(0) is not a thing; try the documented spellings in order."""
    for expr in ("mod.entry(freedom.exe)", "mod.entry(probe_target.exe)",
                 "mod.entry($exe)", "mod.entry(mod.main())",
                 "mod.entry(ImageBaseAddress)"):
        try:
            val, ok = c.eval_sync(expr)
        except Exception as e:  # noqa: BLE001
            print(f"  {expr} -> raised {type(e).__name__}: {e}")
            continue
        print(f"  {expr} -> {hex(val) if ok else '<fail>'} (ok={ok})")
        if ok and val:
            return val
    return 0


def probe_fast_resume_ab(c):
    """A12 needs the .dd64 history cleared, otherwise `go` stops on a stale bp."""
    print("\n=== A12: SetBreakpointFastResume A/B (clean breakpoint DB) ===")
    mod = os.path.basename(TARGET).lower()
    entry_expr = f"mod.entry({mod})"
    observed = {}

    for fr in (False, True):
        # Restart through the verified path so both legs start from the same state.
        c.cmd_sync("stop")
        time.sleep(0.4)
        queued, executed, _ = c.dbg_cmd_exec(f'init "{TARGET}"', 25)
        time.sleep(1.5)
        c.clear_breakpoint(None)          # B1: the .dd64 db re-adds old breakpoints
        time.sleep(0.3)

        entry, ok = c.eval_sync(entry_expr)
        if not ok or not entry:
            print(f"  {entry_expr} -> <failed>, aborting A/B")
            return observed
        addr = hex(entry)

        c.cmd_sync(f"bp {addr}")
        c.cmd_sync(f"SetBreakpointFastResume {addr}, {1 if fr else 0}")
        c.cmd_sync("go")
        time.sleep(1.5)
        _, running, debugging = snap(c, f"fr={fr}")
        cip, cip_ok = c.eval_sync("cip")
        observed[fr] = (running, debugging, cip if cip_ok else None)
        print(f"  FR={int(fr)} -> running={running} debugging={debugging} "
              f"cip={hex(cip) if cip_ok else '<n/a>'} entry={addr} reinit={executed}")

    print(f"  RESULT: {observed}")
    plain, fast = observed.get(False), observed.get(True)
    if plain and fast:
        if plain[0] is False and fast[0] is True:
            print("  VERDICT: FastResume works (plain bp stops, FR passes through)")
        elif plain[0] is False and fast[0] is False:
            print("  VERDICT: FastResume is a no-op — the breakpoint still stops")
        else:
            print("  VERDICT: inconclusive (see running/debugging above)")
    return observed


def main():
    global TARGET
    if not os.path.isfile(TARGET):
        print(f"target not found: {TARGET}")
        return 2
    print(f"debugger: {DBG}")
    print(f"target  : {TARGET}")
    c = X64DbgClient(x64dbg_path=DBG)
    try:
        sid = c.start_session(TARGET)
        print(f"session: {sid}")
        time.sleep(1.0)
        snap(c, "start")
        probe_rerun(c)
        probe_fast_resume_ab(c)
        probe_init(c)
    finally:
        try:
            c.terminate_session()
        except Exception as e:  # noqa: BLE001
            print(f"terminate raised: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
