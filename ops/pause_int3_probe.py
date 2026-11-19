"""int3 兜底的两个细节实验：
  1. 停住后 cip 是否有效（上下文是否可读）
  2. 恢复执行时注入线程怎么收尾：terminate vs 让它执行 ret 自己退出

页面布局：CC C3 —— 线程命中 CC 停住（cip=page+1 指向 ret），go 后执行 ret 退出。
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"


def state(c):
    if not c.is_debugging():
        return "dead"
    return "running" if c.is_running() else "paused"


def main():
    c = X64DbgClient(DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        c.go()
        time.sleep(1.0)

        page = c.virt_alloc(0x1000)
        c.write_memory(page, b"\xCC\xC3" + b"\xCC" * 0x3E)
        tid = c.thread_create(page, 0)
        print(f"page={hex(page)} tid={tid}")

        c.go()
        stopped = c.wait_until_stopped(timeout=3)
        cip, ok = c.eval_sync("cip")
        print(f"stopped={stopped} state={state(c)} cip={hex(cip) if ok else '?'} ok={ok}")

        # 寄存器上下文是否可用
        try:
            rax = c.get_reg("rax")
            print(f"rax={hex(rax)}")
        except Exception as e:
            print("get_reg:", e)

        # 恢复：不 terminate，让它执行 ret 自己退出
        t = time.time()
        c.go()
        time.sleep(0.8)
        print(f"after go (no terminate): state={state(c)} alive={c.is_debugging()} ({(time.time()-t)*1000:.0f} ms)")
        print("debugee_pid =", c.debugee_pid())

        # 再 pause 一次确认会话没坏
        r = c.pause(force=False)
        print(f"pause again -> {r} state={state(c)}")
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)


if __name__ == "__main__":
    main()
