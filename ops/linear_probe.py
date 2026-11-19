"""local.16 探针：插件内线性分析（ANALYSE_LINEAR）。

验证四件事：
1. 一次 IPC 拿全模块 xref 边（不再逐条反汇编）
2. 只扫可执行页（不产生 PE 头/.data 的假边）
3. 缓存命中后 xref 基本免费
4. 与旧 deep 路径的耗时对比

用法:
    C:\\Python314\\python.exe ops\\linear_probe.py [target.exe]
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from x64dbg_automate import X64DbgClient  # noqa: E402
from x64dbg_automate import local_ext  # noqa: E402
from x64dbg_automate import mcp_server as S  # noqa: E402

DBG = os.environ.get("X64DBG_EXE", r"D:\toolkit\dbg\release\x64\x64dbg.exe")
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"D:\tmp\Freedom.exe"


def main():
    print(f"debugger: {DBG}")
    print(f"target  : {TARGET}")
    c = X64DbgClient(x64dbg_path=DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        S._client = c
        lo, length = local_ext._default_range(c, "", 0)
        print(f"module  : {hex(lo)} size={length:,}")

        segs = local_ext._exec_ranges(c, lo, length)
        print(f"exec    : {len(segs)} segment(s), "
              f"{sum(s for _, s in segs):,} bytes of {length:,} ({100*sum(s for _, s in segs)/length:.0f}%)")

        # --- 1. 工具路径（只扫可执行页）+ 冷缓存 ---
        t0 = time.time()
        msg = local_ext.analyse_linear("")
        cold = (time.time() - t0) * 1000
        print(f"\n=== analyse_linear (cold) ===\n  {msg}\n  wall={cold:.0f} ms")

        index, stats = local_ext._linear_edges(c, lo, length)
        print(f"  distinct targets: {stats['targets']:,}")

        # --- 2. 用真实 target 验证命中 + 缓存 ---
        if index:
            to = max(index.items(), key=lambda kv: len(kv[1]))[0]
            n = len(index[to])
            t1 = time.time()
            out1 = local_ext.xref(hex(to))
            d1 = (time.time() - t1) * 1000
            t2 = time.time()
            out2 = local_ext.xref(hex(to))
            d2 = (time.time() - t2) * 1000
            print(f"\n=== xref({hex(to)}), referenced {n}x ===")
            print(f"  first  call: {d1:.0f} ms")
            print(f"  second call: {d2:.0f} ms (cached)")
            for line in out1.splitlines()[:4]:
                print("   ", line)

        # --- 3. 旧 deep 路径对比 ---
        # 旧路径每条指令一次 IPC，_xref_deep 在这里只作参考（它按 tgt 提前退出，
        # 拿 tgt=0 时等于空转）。历史实测：300 KB 模块 deep=True 需 39 s。
        print("\n=== reference ===")
        print(f"  plugin  : {stats['instrs']:,} instrs / {stats['edges']:,} edges in {stats['ms']} ms")
        print("  old deep: one disassemble_at IPC per instruction (measured 39 s on a 300 KB module)")
        return 0
    finally:
        try:
            c.terminate_session()
        except Exception as e:  # noqa: BLE001
            print(f"terminate raised: {e}")


if __name__ == "__main__":
    sys.exit(main())
