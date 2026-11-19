"""Verify script_run(expect=...) turns a half-run script into an explicit failure."""
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from x64dbg_automate import X64DbgClient  # noqa: E402

DBG = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
TARGET = r"C:\Windows\System32\cmd.exe"
TMP = pathlib.Path(tempfile.gettempdir()) / "x64dbg_expect_probe"
TMP.mkdir(exist_ok=True)

GOOD = "log E2E_EXPECT_GOOD\nlblset cip, \"GOOD_LBL\"\nlog PROBE_DONE_GOOD\n"
BAD = "log E2E_EXPECT_BAD\nthisisnotacommand\nlog PROBE_DONE_BAD\n"


def main():
    c = X64DbgClient(DBG)
    try:
        c.start_session(TARGET, clean_breakpoints=True)
        for name, body, sentinel in (("good", GOOD, "PROBE_DONE_GOOD"),
                                     ("bad", BAD, "PROBE_DONE_BAD"),
                                     ("bad_noexpect", BAD, "")):
            p = TMP / f"{name}.x64dbg"
            p.write_text(body, encoding="utf-8")
            c.script_load(str(p))
            ok, msg = c.script_run(0, expect=sentinel)
            print(f"{name:<13} ok={ok!s:<5} {msg[:150]}")
    finally:
        try:
            c.terminate_session()
        except Exception as e:
            print("terminate:", e)


if __name__ == "__main__":
    main()
