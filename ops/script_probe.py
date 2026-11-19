"""Probe x64dbg script commands, v3 — 普通命令必须经 scriptcmd 转发。

v1/v2 的教训：`setlabel`/`setreg`/`exec`/`if` 直接写会中止脚本，但那不是「命令
不支持」，而是**脚本引擎只认脚本命令**（docs/commands/script：log/msg/msgyn/
pause/ret/error/invalid/call/Jxx/scriptcmd/...），普通调试命令要 `scriptcmd`
转发。条件也不是 if 块，而是 cmp + Jxx + 标签。

本脚本验证该结论，并顺带确认 scriptcmd setlabel 是否真能写进标注库。
"""
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\cmd.exe"
TMP = pathlib.Path(tempfile.gettempdir()) / "x64dbg_script_probe3"
TMP.mkdir(exist_ok=True)

CASES = [
    ("sc_log", "scriptcmd log E2E_SC_LOG", None),
    ("sc_setlabel_q", 'scriptcmd setlabel cip, "SC_L1"', "label"),
    ("sc_setlabel_p", "scriptcmd setlabel cip, SC_L2", "label"),
    ("sc_setcomment", 'scriptcmd setcomment cip, "SC_C1"', "comment"),
    ("sc_setreg", "scriptcmd setreg rax, 111", "rax"),
    ("sc_bp", "scriptcmd bp cip", "bp"),
    ("sc_exec_bad", "scriptcmd exec log X", None),
    ("sc_label_cmd", 'scriptcmd label cip, "SC_L3"', "label"),
    ("cmp_jz", "var e2e_c, 1\ncmp e2e_c, 1\njz SKIP_ME\nlog E2E_NOT_JUMPED\nSKIP_ME:\nlog E2E_JUMPED", None),
    ("jmp_label", "jmp GO_HERE\nlog E2E_SKIPPED\nGO_HERE:\nlog E2E_ARRIVED", None),
]


def log_lines(client):
    total, lines, *_ = client.get_log()
    return total, lines or []


def main():
    client = X64DbgClient(DBG)
    rows = []
    try:
        client.start_session(TARGET, clean_breakpoints=True)
        cip, _ = client.eval_sync("cip")
        print("target pid", client.debugee_pid(), "cip", hex(cip), "\n")
        for name, body, extra in CASES:
            script = f"log E2E_B_{name}\n{body}\nlog E2E_E_{name}\n"
            path = TMP / f"{name}.x64dbg"
            path.write_text(script, encoding="utf-8")
            client.script_load(str(path))
            t0, _ = log_lines(client)
            client.script_run(0)

            # 轮询到日志稳定（最多 3 s）
            deadline = time.time() + 3.0
            text = ""
            while time.time() < deadline:
                total, lines = log_lines(client)
                text = "\n".join(lines[-60:])
                if f"E2E_E_{name}" in text:
                    break
                time.sleep(0.2)
            ok_end = f"E2E_E_{name}" in text
            ok_begin = f"E2E_B_{name}" in text
            verdict = "PASS" if ok_end else ("ABORT" if ok_begin else "NO-RUN")

            # 错误行（去掉我们自己的标记和模态框噪音）
            err = [ln for ln in text.splitlines()
                   if f"E2E_B_{name}" not in ln and f"E2E_E_{name}" not in ln
                   and "closed 1 modal dialog" not in ln and "脚本执行完毕" not in ln]
            extra_out = ""
            if extra == "label":
                extra_out = client.get_label_at(cip) or ""
            elif extra == "comment":
                extra_out = client.get_comment_at(cip) or ""
            elif extra == "rax":
                extra_out = hex(client.get_reg("rax"))
            elif extra == "bp":
                extra_out = str(len(client.get_breakpoints(1)))

            rows.append((name, verdict, extra_out, " / ".join(err[-2:])[-120:]))
            print(f"{name:<16} {verdict:<7} extra={extra_out!r:<24} {rows[-1][3][:90]}")
            client.cmd_sync("bpc")
    finally:
        try:
            client.terminate_session()
        except Exception as e:
            print("terminate:", e)

    print("\n=== 汇总 ===")
    for name, verdict, extra, err in rows:
        print(f"{verdict:<7} {name:<16} extra={extra!r:<22} {err[:80]}")
    print("\nPASS :", [n for n, v, *_ in rows if v == "PASS"])
    print("ABORT:", [n for n, v, *_ in rows if v == "ABORT"])


if __name__ == "__main__":
    main()
