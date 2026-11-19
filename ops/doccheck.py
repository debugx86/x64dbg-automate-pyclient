"""技能包四份文档的一致性校验（工具覆盖 / 路径存在 / 版本坐标）。"""
import json
import pathlib
import re

ROOT = pathlib.Path(r"D:\toolkit\x64dbg-automate\skill\x64dbg-automate-guide")
TOOLS = {r["name"] for r in json.loads(
    pathlib.Path(r"C:\Users\debugx86\AppData\Local\Temp\tools17.json").read_text(encoding="utf-8"))}

files = {
    "api_reference": ROOT / "references" / "api_reference.md",
    "SKILL": ROOT / "SKILL.md",
    "README": ROOT / "README.md",
    "BUG记录": ROOT / "BUG记录.md",
}
texts = {k: p.read_text(encoding="utf-8") for k, p in files.items()}

print(f"== 工具总数基线: {len(TOOLS)} ==")

# 1) api_reference 必须覆盖全部 68 个工具
missing = sorted(t for t in TOOLS if f"`{t}`" not in texts["api_reference"])
print(f"[1] api_reference 未提到的工具: {missing or '无'}")

# 2) 文档里提到的工具名必须真实存在（只查带下划线的 snake_case 段）
known_mcp = TOOLS | {
    # Python 方法 / 内部函数 / 命令，不算 MCP 工具
    "start_session_attach", "wait_for_debug_event", "get_latest_debug_event", "peek_latest_debug_event",
    "watch_debug_event", "unwatch_debug_event", "clear_debug_events", "log_event_queue_maxlen",
    "set_breakpoint", "set_hardware_breakpoint", "set_memory_breakpoint", "clear_breakpoint",
    "clear_hardware_breakpoint", "clear_memory_breakpoint", "toggle_breakpoint",
    "toggle_hardware_breakpoint", "toggle_memory_breakpoint", "get_breakpoints", "reset_breakpoints",
    "restart_session", "close_dialog_boxes", "suspend_debuggee", "resume_debuggee", "analyse_linear",
    "analyse_range", "read_memory", "write_memory", "read_memory_many", "read_word", "read_dword",
    "read_qword", "virt_alloc", "virt_free", "virt_protect", "virt_query", "memset", "get_reg", "set_reg",
    "get_regs", "assemble_at", "disassemble_at", "eval_sync", "cmd_sync", "execute_command", "module_path",
    "get_symbol_at", "get_label_at", "get_comment_at", "set_label_at", "del_label_at", "set_comment_at",
    "del_comment_at", "gui_show_reference_view", "trace_into", "trace_over", "trace_set_log_file",
    "thread_create", "thread_terminate", "thread_pause", "thread_resume", "switch_thread",
    "get_setting_str", "set_setting_str", "get_setting_int", "set_setting_int", "get_log", "hide_debugger_peb",
    "script_load", "script_run", "dbg_cmd_exec", "xref_count_at", "xref_type_at", "xref_get", "xref_add",
    "function_type_at", "memmap", "check_valid_read_ptr", "wait_until_debugging", "wait_until_not_debugging",
    "wait_until_running", "wait_until_stopped", "wait_cmd_ready", "wait_for_session", "attach_session",
    "detach_session", "terminate_session", "list_sessions", "connect_remote", "load_executable",
    "unload_executable", "debugee_pid", "debugee_bitness", "debugger_is_elevated", "get_debugger_pid",
    "get_debugger_version", "get_setting", "set_setting", "stepi", "stepo", "skip", "ret", "go", "pause",
    "set_label", "set_comment", "close_dialog", "decompile_step", "state_snapshot", "state_diff",
    "yara_scan", "enum_imports", "find_xrefs", "full_sweep", "linear_probe", "b1_probe", "xref_baseline",
    "a11_probe", "a12_cond_probe", "docstring_audit", "local_patch_info", "_send_request",
    "_launch_x64dbg", "_pe_bitness", "_resolve_launcher", "_scan_all", "_scan_bytes", "_xref_deep",
    "_linear_edges", "_exec_ranges", "_image_pages", "_default_range", "_parse_pattern", "_get_xauto_compat_version",
    "_assert_connection_compat", "restore_stock", "upgrade_upstream", "x64dbg_automate", "x64dbg_automate_mcp",
}
suspicious = {}
for name, txt in texts.items():
    hits = set(re.findall(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`", txt))
    bad = sorted(h for h in hits if h not in known_mcp and not h.startswith(("event_", "bp_", "mem_", "page_", "set_bp")))
    if bad:
        suspicious[name] = bad
print(f"[2] 文档里疑似不存在的 snake_case 标识: {suspicious or '无'}")

# 3) 版本坐标：当前版本表述里不该再出现 local.16 作为"当前"
print("[3] 当前版本表述抽查")
for name, txt in texts.items():
    v17 = txt.count("local.17")
    v16 = txt.count("local.16")
    print(f"    {name:<14} local.17 x{v17:<3} local.16 x{v16}")

# 4) 绝对路径存在性抽查（只查 README / SKILL 里含 D:\ 且以已知扩展名或目录结尾的）
paths = set()
for name in ("README", "SKILL"):
    for m in re.finditer(r"D:\\[^\s`'\"（）)，。]*", texts[name]):
        s = m.group(0).rstrip("\\")
        if len(s) > 12 and ("\\" in s[3:]):
            paths.add(s)
missing_paths = []
for s in sorted(paths):
    q = pathlib.Path(s)
    if any(ch in s for ch in "<>*|") or s.endswith((".exe", ".dll", ".dp64", ".dp32", ".json", ".md", ".py", ".ini", ".ps1", ".log")):
        if not q.exists():
            missing_paths.append(s)
print(f"[4] 文档引用的绝对路径缺失: {missing_paths or '无'}")

# 5) plugin 分发件哈希与部署件一致
import hashlib
pairs = [
    (ROOT / "plugin/x64/plugins/x64dbg-automate.dp64", pathlib.Path(r"D:\toolkit\dbg\release\x64\plugins\x64dbg-automate.dp64")),
    (ROOT / "plugin/x32/plugins/x64dbg-automate.dp32", pathlib.Path(r"D:\toolkit\dbg\release\x32\plugins\x64dbg-automate.dp32")),
    (ROOT / "plugin/x64/plugins/libzmq-mt-4_3_5.dll", pathlib.Path(r"D:\toolkit\dbg\release\x64\plugins\libzmq-mt-4_3_5.dll")),
    (ROOT / "plugin/x32/plugins/libzmq-mt-4_3_5.dll", pathlib.Path(r"D:\toolkit\dbg\release\x32\plugins\libzmq-mt-4_3_5.dll")),
]
for a, b in pairs:
    ha = hashlib.sha256(a.read_bytes()).hexdigest()[:16] if a.exists() else "MISSING"
    hb = hashlib.sha256(b.read_bytes()).hexdigest()[:16] if b.exists() else "MISSING"
    print(f"[5] {'OK ' if ha == hb and ha != 'MISSING' else 'DIFF'} {a.name:<24} pkg={ha} deployed={hb}")

# 6) api_reference 的 4.x 分组标题里写的数量，必须与该组实际列出的工具数一致
secs = re.split(r"^### (4\.\d+) (.*)$", texts["api_reference"], flags=re.M)
bad_counts = []
for i in range(1, len(secs) - 1, 3):
    num, title, body = secs[i], secs[i + 1], secs[i + 2].split("\n## ")[0]
    m = re.search(r"（(\d+)）", title)
    if not m:
        continue
    names = []
    for line in body.splitlines():
        if line.startswith("| `"):
            cell = line.split("|")[1]
            names += [x.group(1) for x in re.finditer(r"`([a-z][a-z0-9_]+)`", cell) if x.group(1) in TOOLS]
    if len(names) != int(m.group(1)):
        bad_counts.append(f"{num} 标题写 {m.group(1)}，实际 {len(names)}")
print(f"[6] api_reference 分组计数不符: {bad_counts or '无'}")

