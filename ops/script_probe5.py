"""Probe v5 — 决定性验证：正确命令名是 lblset / cmtset / `reg=value`。

v4 发现库层 API 走的是 `lblset` / `cmtset` / `<reg>=0x..`，而不是 `setlabel` /
`setcomment` / `setreg`。也就是说 v1–v3 的「脚本里标注不可用」很可能是**命令名
不存在**造成的假象（脚本引擎在第一条失败命令处整体中止）。

本脚本在脚本里直接写正确命令名，用 get_label_at / get_comment_at / get_reg 读回。
"""
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\cmd.exe"
TMP = pathlib.Path(tempfile.gettempdir()) / "x64dbg_script_probe5"
TMP.mkdir(exist_ok=True)

CASES = [
    ("lblset_direct", 'lblset cip, "S5_LBL"', "label"),
    ("cmtset_direct", 'cmtset cip, "S5_CMT"', "comment"),
    ("lblset_sc", 'scriptcmd lblset cip, "S5_LBL_SC"', "label"),
    ("reg_assign", "rax=0x6F", "rax"),
    ("reg_assign_sc", "scriptcmd rcx=0x7A", "rcx"),
]


def main():
    c = X64DbgClient(DBG)
    rows = []
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        cip, _ = c.eval_sync("cip")
        print("cip", hex(cip))
        for name, body, extra in CASES:
            script = f"log E2E_B_{name}\n{body}\nlog E2E_E_{name}\n"
            p = TMP / f"{name}.x64dbg"
            p.write_text(script, encoding="utf-8")
            c.script_load(str(p))
            c.script_run(0)
            deadline = time.time() + 3.0
            text = ""
            while time.time() < deadline:
                total, lines, *_ = c.get_log()
                text = "\n".join(lines[-40:])
                if f"E2E_E_{name}" in text:
                    break
                time.sleep(0.2)
            verdict = "PASS" if f"E2E_E_{name}" in text else ("ABORT" if f"E2E_B_{name}" in text else "NO-RUN")
            if extra == "label":
                got = c.get_label_at(cip)
            elif extra == "comment":
                got = c.get_comment_at(cip)
            else:
                got = hex(c.get_reg(extra))
            rows.append((name, verdict, got))
            print(f"{name:<16} {verdict:<7} {extra}={got!r}")
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)

    print("\n=== 汇总 ===")
    for n, v, g in rows:
        print(f"{v:<7} {n:<16} {g!r}")


if __name__ == "__main__":
    main()
