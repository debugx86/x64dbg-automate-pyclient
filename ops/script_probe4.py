"""Probe v4 — 把「命令通道」和「脚本引擎」的界线画清。

v3 已知：脚本里 `scriptcmd setlabel ...` / `scriptcmd setreg ...` 会静默中止。
本脚本验证同一批命令走 `cmd_sync`（= dbg_cmd_exec，真命令队列）是否成功，
以区分「命令不可用」和「脚本引擎上下文限制」。
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\cmd.exe"


def main():
    c = X64DbgClient(DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        cip, _ = c.eval_sync("cip")
        print("cip", hex(cip), "rax_before", hex(c.get_reg("rax")))

        print("\n--- setreg ---")
        ok = c.cmd_sync("setreg rax, 111")
        print("cmd_sync ->", ok, "rax_after", hex(c.get_reg("rax")))

        print("\n--- setlabel ---")
        ok = c.cmd_sync('setlabel cip, "SC_CMD_LBL"')
        print("cmd_sync ->", ok, "label_at_cip =", repr(c.get_label_at(cip)))

        print("\n--- setcomment ---")
        ok = c.cmd_sync('setcomment cip, "SC_CMD_CMT"')
        print("cmd_sync ->", ok, "comment_at_cip =", repr(c.get_comment_at(cip)))

        print("\n--- label (别名) ---")
        ok = c.cmd_sync('label cip, "SC_CMD_LBL2"')
        print("cmd_sync ->", ok, "label_at_cip =", repr(c.get_label_at(cip)))

        print("\n--- exec（不该存在）---")
        ok = c.cmd_sync("exec log X")
        print("cmd_sync ->", ok)

        print("\n--- 库层 API 对照 ---")
        print("set_label_at ->", c.set_label_at(cip, "SC_API_LBL"), "read:", repr(c.get_label_at(cip)))
        print("set_comment_at ->", c.set_comment_at(cip, "SC_API_CMT"), "read:", repr(c.get_comment_at(cip)))

        total, lines, *_ = c.get_log()
        tail = [ln for ln in (lines or [])[-14:] if "modal dialog" not in ln]
        print("\n--- 日志尾 ---")
        for ln in tail:
            print("   ", ln[:120])
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)


if __name__ == "__main__":
    main()
