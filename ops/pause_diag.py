"""诊断：ScyllaHide 启用 + 目标阻塞态，直接走 int3 兜底为什么变成 running/dead。"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"


def st(c):
    try:
        return "running" if c.is_running() else ("paused" if c.is_debugging() else "dead")
    except Exception as e:
        return f"err({e})"


def logtail(c, n=18):
    try:
        total, lines, *_ = c.get_log()
        for ln in (lines or [])[-n:]:
            if "modal dialog" not in ln:
                print("    |", ln[:140])
    except Exception as e:
        print("    log err", e)


def main():
    c = X64DbgClient(DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        c.go()
        time.sleep(1.0)
        peb, ok = c.eval_sync("peb()")
        print("peb ok:", ok, hex(peb) if ok else "", "bd:", c.read_memory(peb + 2, 1).hex() if ok else "?")
        print("gate_closed:", c._being_debugged_gate_closed(), "state:", st(c))

        t = time.time()
        r = c._pause_via_int3_page()
        print(f"int3 -> {r} {(time.time()-t)*1000:.0f} ms state={st(c)} pid={c.debugee_pid()}")
        logtail(c)
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)


if __name__ == "__main__":
    main()
