"""A12 定性探针：`SetBreakpointFastResume` 到底在什么条件下才「不暂停」。

官方文档（docs/commands/conditional-breakpoint-control/SetBreakpointFastResume.md）:
    "If this flag is set and the break condition doesn't evaluate to break, no GUI,
     plugin, logging or any other action will be performed, except for incrementing
     the hit counter."

即：fast resume 不是「命中就继续」，而是「条件为假时彻底静默」。所以要用
`SetBreakpointCondition addr, "0"`（恒假）配合。

用法:
    C:\\Python314\\python.exe ops\\a12_cond_probe.py [target.exe]
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = os.environ.get("X64DBG_EXE", r"D:\toolkit\dbg\release\x64\x64dbg.exe")
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\winver.exe"
MOD = os.path.basename(TARGET).lower()


def snapshot(c):
    try:
        return c.is_running(), c.is_debugging()
    except Exception as e:  # noqa: BLE001
        return f"<{e}>", f"<{e}>"


def main():
    c = X64DbgClient(x64dbg_path=DBG)
    rows = []
    try:
        c.start_session(TARGET)
        time.sleep(1.0)
        entry, ok = c.eval_sync(f"mod.entry({MOD})")
        if not ok or not entry:
            print("cannot resolve entry")
            return 2
        addr = f"0x{entry:x}"
        print(f"entry = {addr}")

        cases = [
            ("plain bp", None, 0),
            ("bp + FR=1 (no condition)", None, 1),
            ("bp + cond 0", "0", 0),
            ("bp + cond 0 + FR=1", "0", 1),
        ]

        for label, cond, fr in cases:
            c.cmd_sync("stop")
            time.sleep(0.3)
            c.dbg_cmd_exec(f'init "{TARGET}"', 25)
            time.sleep(1.2)
            c.clear_breakpoint(None)
            time.sleep(0.2)

            c.cmd_sync(f"bp {addr}")
            if cond is not None:
                c.cmd_sync(f'SetBreakpointCondition {addr}, "{cond}"')
            c.cmd_sync(f"SetBreakpointFastResume {addr}, {fr}")

            log_before = len(c.get_log(0, 500, "")[1])
            c.cmd_sync("go")
            time.sleep(1.2)
            log_entries = c.get_log(0, 500, "")[1]
            log_after = len(log_entries)
            new_lines = [ln for e in log_entries[log_before:] for ln in e.splitlines() if ln.strip()]

            running, debugging = snapshot(c)
            hits = None
            fr_state = cond_state = None
            try:
                from x64dbg_automate.models import BreakpointType
                for bp in c.get_breakpoints(BreakpointType.BpNormal):
                    if bp.addr == entry:
                        hits = bp.hitCount
                        fr_state = bp.fastResume
                        cond_state = bp.breakCondition
                        break
            except Exception as e:  # noqa: BLE001
                hits = f"<{type(e).__name__}: {e}>"
            cip, cip_ok = c.eval_sync("cip")
            row = (label, running, debugging, hits, hex(cip) if cip_ok else None,
                   log_after - log_before, fr_state, cond_state, new_lines)
            rows.append(row)
            print(f"  {label:<26} running={running!s:<5} hits={hits!s:<4} "
                  f"fr={fr_state} cond={cond_state!r} "
                  f"log+={row[5]:<3} cip={row[4]}")
            for ln in new_lines[:4]:
                print(f"       log> {ln[:150]}")
            if running is True:
                c.pause()
                time.sleep(0.3)

        print("\n结论：")
        for label, running, debugging, hits, cip, log_delta, *_ in rows:
            if running is True and hits:
                print(f"  [{label}] 命中 {hits} 次且未暂停 -> 静默继续 (log+{log_delta})")
            elif running is False and hits:
                print(f"  [{label}] 命中 {hits} 次但停住了 -> 会中断 (log+{log_delta})")
            else:
                print(f"  [{label}] running={running} hits={hits} log+{log_delta}")
    finally:
        try:
            c.terminate_session()
        except Exception as e:  # noqa: BLE001
            print(f"terminate raised: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
