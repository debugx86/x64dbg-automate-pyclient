"""ScyllaHide 启用态：pause() 默认路径与 fast 路径的最终组合验证。

预期：
  default -> True（写回 BeingDebugged，~5 s，停在真实执行点，cip 有效）
  fast    -> False（int3 注入线程被 NtSetInformationThreadHook 隐藏；不得假阳性）
  两条路径都不得把会话搞坏（结束后仍能 go / pause）。
"""
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
    except Exception:
        return "?"


def main():
    c = X64DbgClient(DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        c.go()
        time.sleep(1.0)
        peb, ok = c.eval_sync("peb()")
        print("BeingDebugged:", c.read_memory(peb + 2, 1).hex() if ok else "?")

        for label, kw in (("fast=True", {"fast": True}), ("default", {})):
            t = time.time()
            r = c.pause(**kw)
            dt = (time.time() - t) * 1000
            cip, ok2 = c.eval_sync("cip") if r else (0, False)
            print(f"pause({label}) -> {r} {dt:.0f} ms state={st(c)} cip={hex(cip) if ok2 else '-'}")
            if not c.is_running():
                c.go()
                time.sleep(1.0)
        print("final:", st(c), "pid", c.debugee_pid())
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)


if __name__ == "__main__":
    main()
