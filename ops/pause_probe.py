"""C3 机制自查 + pause 三档可行性验证（ScyllaHide 当前状态由外部决定）。

步骤：
  1. 反汇编 ntdll!DbgUiRemoteBreakin，确认两道门（PEB+2 / TEB+0x17EE&0x20）
  2. 起 cmd.exe → go（阻塞在 ReadFile）→ 确认 running 态能否取 peb()
  3. 依次试：原生 pause / 写回 PEB.BeingDebugged / int3 页注入
每次试验后把目标放回 running，方便下一档。
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402
from x64dbg_automate.events import EventType  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"


def state(c):
    return "running" if c.is_running() else ("paused" if c.is_debugging() else "not-debugging")


def main():
    c = X64DbgClient(DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)

        # --- 1. 反汇编 break-in 线程入口 ---
        addr, ok = c.eval_sync("ntdll:DbgUiRemoteBreakin")
        print(f"[1] ntdll:DbgUiRemoteBreakin = {hex(addr) if ok else 'FAIL'} ok={ok}")
        if ok and addr and not c.is_running():
            cur = addr
            for _ in range(12):
                ins = c.disassemble_at(cur)
                if not ins:
                    break
                print(f"    {hex(cur)}  {ins.instruction}")
                cur += ins.instr_size

        # --- 2. go 进阻塞态 ---
        c.go()
        time.sleep(1.2)
        print(f"[2] after go: {state(c)}")
        peb, ok = c.eval_sync("peb()")
        print(f"    peb() = {hex(peb) if ok else 'FAIL'} ok={ok}")
        if ok and peb:
            raw = c.read_memory(peb + 2, 1)
            print(f"    PEB.BeingDebugged = {raw.hex()}")

        # --- 3a. 原生 pause ---
        t = time.time()
        r = c.pause(force=False) if "force" in c.pause.__code__.co_varnames else c.pause()
        print(f"[3a] native pause -> {r} ({((time.time()-t)*1000):.0f} ms) state={state(c)}")
        if not c.is_running():
            c.go()
            time.sleep(1.0)

        # --- 3b. 写回 BeingDebugged ---
        if ok and peb:
            t = time.time()
            orig = c.read_memory(peb + 2, 1)
            c.write_memory(peb + 2, b"\x01")
            time.sleep(0.3)
            try:
                c.cmd_sync("pause")
            except Exception as e:
                print("    cmd_sync pause:", e)
            stopped = c.wait_until_stopped(timeout=4)
            c.write_memory(peb + 2, orig)
            print(f"[3b] beingdebugged -> {stopped} ({((time.time()-t)*1000):.0f} ms) state={state(c)}")
            if not c.is_running():
                c.go()
                time.sleep(1.0)

        # --- 3c. int3 页注入 ---
        t = time.time()
        page = c.virt_alloc(0x1000)
        print(f"    page = {hex(page) if page else 'FAIL'}")
        if page:
            c.write_memory(page, b"\xCC")
            tid = c.thread_create(page, 0)
            print(f"    tid = {tid}")
            c.go()
            stopped = c.wait_until_stopped(timeout=4)
            print(f"[3c] int3 page -> {stopped} ({((time.time()-t)*1000):.0f} ms) state={state(c)}")
            if stopped:
                cip, ok2 = c.eval_sync("cip")
                print(f"    cip = {hex(cip) if ok2 else '?'} (page={hex(page)})")
                if tid:
                    try:
                        print("    terminate injected thread ->", c.thread_terminate(tid))
                    except Exception as e:
                        print("    terminate:", e)
            try:
                c.virt_free(page)
            except Exception as e:
                print("    free:", e)
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)


if __name__ == "__main__":
    main()
