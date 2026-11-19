"""C3 判决实验：ScyllaHide 启用/禁用 × 三种暂停路径。

背景：x64dbg 的 break-in 线程是 ntdll!DbgUiRemoteBreakin，它先看 PEB.BeingDebugged，
为 0 就 RtlExitUserThread，连 int3 都不产生。ScyllaHide 的 PebBeingDebugged 正好写 0。

本脚本对当前 ScyllaHide 状态（.dp64 / .dp64.off）跑同一套矩阵：
  A 原生两次 pause（force=False）
  B 只走 PEB.BeingDebugged 写回（_pause_via_being_debugged）
  C 只走 int3 页注入（_pause_via_int3_page）
每档结束都放回 running，最后检查会话仍健康。

用法：python ops/pause_matrix.py [--label 标签]
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"
LABEL = sys.argv[sys.argv.index("--label") + 1] if "--label" in sys.argv else "?"


def state(c):
    if not c.is_debugging():
        return "dead"
    return "running" if c.is_running() else "paused"


def reset_to_running(c):
    try:
        if not c.is_running():
            c.go()
        time.sleep(1.0)
    except Exception as e:
        print("    reset:", e)


def main():
    c = X64DbgClient(DBG)
    rows = []
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        c.go()
        time.sleep(1.2)                      # 进入 ReadFile 阻塞
        peb, ok = c.eval_sync("peb()")
        bd = c.read_memory(peb + 2, 1).hex() if ok and peb else "?"
        print(f"[{LABEL}] state={state(c)} peb={hex(peb) if ok else '?'} BeingDebugged={bd}")

        for name, fn in (
            ("A_native", lambda: c.pause(force=False)),
            ("B_beingdebugged", c._pause_via_being_debugged),
            ("C_int3_page", c._pause_via_int3_page),
        ):
            t = time.time()
            try:
                r = fn()
            except Exception as e:
                r = f"EXC {type(e).__name__}: {e}"
            dt = (time.time() - t) * 1000
            st = state(c)
            detail = ""
            if st == "paused":
                cip, ok2 = c.eval_sync("cip")
                detail = f"cip={hex(cip) if ok2 else '?'}"
            print(f"[{LABEL}] {name:<16} -> {r!s:<6} {dt:7.0f} ms state={st} {detail}")
            rows.append((name, r, dt, st))
            reset_to_running(c)

        # 注入线程被终止后，会话还能不能正常 go/停
        print(f"[{LABEL}] final state={state(c)} debugee_pid={c.debugee_pid()}")
        ok2 = c.pause(force=False)
        print(f"[{LABEL}] post-check pause -> {ok2} state={state(c)}")
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)

    print(f"\n[{LABEL}] 汇总: " + " | ".join(f"{n}={r}" for n, r, _, _ in rows))


if __name__ == "__main__":
    main()
