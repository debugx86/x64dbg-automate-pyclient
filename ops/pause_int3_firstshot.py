"""local.20 回归：全新会话里，第一次动作就直接调 int3 页兜底，必须停住且上下文可用。

local.19 的缺陷就在这条路径上：x64dbg 在目标 running 时只把断点记进表、不把 0xCC
写进内存，`createthread` 起的线程跑到的还是我们写的 `C3`（ret），于是线程直接退出、
wait_until_stopped 超时。作者矩阵里 C 行显示 True 是因为那一行之前已经成功暂停过一次。
本探针不允许有任何前置 pause —— 只起会话、go 到阻塞、立刻调兜底。
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"

fails = []
c = X64DbgClient(DBG)
try:
    c.start_session(TARGET, clean_breakpoints=True)
    c.go()
    time.sleep(1.2)
    assert c.is_running(), "前置条件不成立：目标没在 running"

    page = getattr(c, "_pause_page", 0)
    print(f"缓存页（应为 0/空）= {page}")
    t = time.time()
    ok = c._pause_via_int3_page()
    ms = int((time.time() - t) * 1000)
    print(f"第一次就直接用 int3 兜底 -> {ok} {ms} ms running={c.is_running()}")
    if not ok:
        fails.append("int3 兜底在全新会话第一次调用仍然失败")

    cip, e = c.eval_sync("cip")
    print(f"停住后 cip = {hex(cip) if e and cip else cip}  (0 表示活动线程被杀)")
    if not (e and cip):
        fails.append("switchthread 没生效：pause 成功但 cip 读不到")

    # 页缓存应已建立，供后续调用复用
    print(f"缓存页已写入 = {hex(int(getattr(c, '_pause_page', 0)))}")
finally:
    try:
        c.terminate_session()
    except Exception as exc:
        print("terminate:", exc)

# 跨会话：terminate 后同对象再开会话，缓存必须已失效
c2 = c
try:
    c2.start_session(TARGET, clean_breakpoints=True)
    c2.go()
    time.sleep(1.0)
    stale = int(getattr(c2, "_pause_page", 0) or 0)
    print(f"新会话里的页缓存 = {hex(stale) if stale else '0（已失效，正确）'}")
    if stale:
        fails.append("terminate/start_session 后 _pause_page 没清零")
    ok2 = c2._pause_via_int3_page()
    print(f"新会话第一次 int3 兜底 -> {ok2}")
    if not ok2:
        fails.append("新会话第一次 int3 兜底失败")
    cip2, e2 = c2.eval_sync("cip")
    print(f"cip = {hex(cip2) if e2 and cip2 else cip2}")
    if not (e2 and cip2):
        fails.append("新会话 cip 读不到")
finally:
    try:
        c2.terminate_session()
    except Exception:
        pass

print("\n结果:", "全部通过" if not fails else "存在问题 -> " + "; ".join(fails))
sys.exit(1 if fails else 0)
