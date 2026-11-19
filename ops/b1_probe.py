"""B1 探针：x64dbg 的 .dd64 断点库跨会话残留，clean_breakpoints 是否真的清干净。

实测背景（2026-11-19）：`bpc` 清空后 terminate_session 不落盘，下次启动 .dd64 又把
TLS/入口断点全恢复 —— 所以"清一次"不能治本，必须每次 start/restart 后清。

用法:
    C:\\Python314\\python.exe ops\\b1_probe.py [target.exe]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from x64dbg_automate import X64DbgClient  # noqa: E402
from x64dbg_automate.models import BreakpointType  # noqa: E402

DBG = os.environ.get("X64DBG_EXE", r"D:\toolkit\dbg\release\x64\x64dbg.exe")
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"D:\tmp\Freedom.exe"


def count_bps(c):
    try:
        return len(c.get_breakpoints(BreakpointType.BpNormal))
    except Exception as e:  # noqa: BLE001
        return f"<{type(e).__name__}: {e}>"


def run_case(label, launch):
    c = X64DbgClient(x64dbg_path=DBG)
    try:
        launch(c)
        n = count_bps(c)
        print(f"  {label:<28} breakpoints = {n}")
        return n
    finally:
        try:
            c.terminate_session()
        except Exception as e:  # noqa: BLE001
            print(f"  terminate raised: {e}")


def main():
    print(f"debugger: {DBG}")
    print(f"target  : {TARGET}")
    print("\n=== B1: .dd64 断点残留 ===")
    baseline = run_case("start_session (默认保留)", lambda c: c.start_session(TARGET))
    cleaned = run_case("start_session (clean=True)",
                       lambda c: c.start_session(TARGET, clean_breakpoints=True))
    restarted = run_case("restart_session (clean=True)",
                         lambda c: (c.start_session(TARGET),
                                    c.restart_session(clean_breakpoints=True)))

    print("\n结论：")
    print(f"  默认启动恢复 {baseline} 个断点（这正是每次被 TLS 断点拦下的原因）")
    print(f"  clean=True 启动后剩 {cleaned} 个 -> {'已清干净' if cleaned == 0 else '仍有残留'}")
    print(f"  restart(clean=True) 后剩 {restarted} 个 -> {'已清干净' if restarted == 0 else '仍有残留'}")
    ok = cleaned == 0 and restarted == 0
    print(f"  VERDICT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
