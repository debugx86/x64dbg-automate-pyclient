"""local.20 定版前的三项定向回归（都是今天实测里暴露出来的点）。

T1 fast 兜底停住后，状态会不会自己漂回 running（清线程的副作用）
T2 script_run(expect=) 的基数修复：上一次运行留下的同名哨兵不能造成假命中
T3 trace_over 独立复测（文档里一直挂在「未实测」）
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"
WS = pathlib.Path(r"C:\Users\debugx86\.qwenworkcn\workspace\mwn8u7bjtkc29xxk")
T1_SCRIPT = str(WS / "t1_lblset_ok.x64dbg")      # 末行 log X1_END
T4_SCRIPT = str(WS / "t4_no_log.x64dbg")         # 不打任何 log

fails = []


def st(c):
    return "running" if c.is_running() else "paused"


def fresh(c):
    c.start_session(TARGET, clean_breakpoints=True)
    c.go()
    time.sleep(1.2)


c = X64DbgClient(DBG)
try:
    # ---------- T1 ----------
    print("=== T1 fast 兜底后的状态稳定性 ===")
    fresh(c)
    ok = c.pause(fast=True)
    cip0, e0 = c.eval_sync("cip")
    print(f"  pause(fast=True) -> {ok} state={st(c)} cip={hex(cip0) if e0 and cip0 else cip0}")
    if not ok:
        fails.append("T1: fast 兜底失败")
    for tick in (1.0, 2.0, 3.0):
        time.sleep(tick)
        print(f"  +{tick * 2:.0f}s state={st(c)}")
        if c.is_running():
            fails.append(f"T1: 停住后在 +{tick * 2:.0f}s 漂回 running")
            break
    c.terminate_session()
    time.sleep(0.8)

    # ---------- T2 ----------
    print("\n=== T2 陈旧哨兵不得造成假命中 ===")
    fresh(c)
    c.pause(force=False)                       # 原生停住，便于跑脚本
    c.script_load(T1_SCRIPT)
    hit = c.script_run(0, expect="X1_END", settle=4.0)
    print(f"  第一次（本次真会打 X1_END）-> ok={hit[0]} {hit[1][:60]}")
    if not hit[0]:
        fails.append("T2: 正常脚本被误判失败")
    c.script_load(T4_SCRIPT)                   # 这次不打任何 log
    stale = c.script_run(0, expect="X1_END", settle=1.0)
    print(f"  第二次（哨兵只存在于上一轮）-> ok={stale[0]} {stale[1][:120]}")
    if stale[0] or "已出现" in stale[1]:
        fails.append("T2: 陈旧哨兵仍被当成本次命中（基数修复没生效）")
    c.terminate_session()
    time.sleep(0.8)

    # ---------- T3 ----------
    # 实测出的用法约束（local.20 首次跑 trace_* 踩出来的）：trace_over / trace_into
    # 必须在"停在代码里"的状态发起。目标阻塞在内核等待（cmd.exe 的 ReadFile）时
    # 发起 trace，命令只进队列不执行：30 s 超时、返回 False、state 漂成 running。
    print("\n=== T3 trace_over / trace_into 用法回归 ===")
    try:
        c.terminate_session()
    except Exception:
        pass
    time.sleep(0.8)
    c.start_session(TARGET, clean_breakpoints=True)      # 停在系统断点，别 go
    print("  系统断点处 state =", st(c))
    t = time.time()
    r = c.trace_over(break_condition="0", max_steps=20, wait_timeout=25)
    print(f"  trace_over(停在代码里) -> {r} {int((time.time() - t) * 1000)} ms state={st(c)}")
    if not r:
        fails.append("T3: trace_over 在系统断点处也失败")
    t = time.time()
    r2 = c.trace_into(break_condition="0", max_steps=20, wait_timeout=25)
    print(f"  trace_into(同样条件)   -> {r2} {int((time.time() - t) * 1000)} ms state={st(c)}")
    if not r2:
        fails.append("T3: trace_into 在系统断点处也失败")
    # 反例 A：running 态发起 trace —— 立即 False
    c.go()
    time.sleep(1.2)
    t = time.time()
    r3 = c.trace_over(break_condition="0", max_steps=20, wait_timeout=6)
    print(f"  反例A(running 态) -> {r3} {int((time.time() - t) * 1000)} ms（预期立即 False）")
    if r3:
        fails.append("T3: running 态 trace 竟然成功")
    # 反例 B：停在内核等待点发起 trace —— 命令进队列但不执行，等满 wait_timeout，
    # 而且会把会话状态推成 running（local.20 首跑就是这样踩的，30 s 才返回 False）
    c.pause(force=True)
    t = time.time()
    r4 = c.trace_over(break_condition="0", max_steps=20, wait_timeout=8)
    ms4 = int((time.time() - t) * 1000)
    print(f"  反例B(等待点 paused) -> {r4} {ms4} ms state={st(c)}（预期超时 False）")
    if r4:
        fails.append("T3: 内核等待态 trace 竟然成功，文档约束需要重写")
finally:
    try:
        c.terminate_session()
    except Exception:
        pass

print("\n结果:", "全部通过" if not fails else "存在问题 -> " + "; ".join(fails))
sys.exit(1 if fails else 0)
