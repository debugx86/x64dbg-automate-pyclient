"""Dump every MCP tool with its parameter schema (no debugger needed)."""
import asyncio
import json
import logging
import pathlib
import sys

sys.path.insert(0, r"D:\toolkit\x64dbg-automate\app")
import x64dbg_automate.mcp_server as S  # noqa: E402
import x64dbg_automate.local_ext as LE  # noqa: E402,F401
import x64dbg_automate.mcp_server_local as _entry  # noqa: E402,F401  触发 register()
from mcp.shared.memory import create_connected_server_and_client_session as cc  # noqa: E402

logging.disable(logging.INFO)
OUT = pathlib.Path(r"C:\Users\debugx86\AppData\Local\Temp\tools17.json")


async def main():
    async with cc(S.mcp._mcp_server) as c:
        tools = (await c.list_tools()).tools
    rows = []
    for t in tools:
        props = t.inputSchema.get("properties", {})
        req = set(t.inputSchema.get("required", []))
        args = []
        for name, spec in props.items():
            ptype = spec.get("type", "?")
            dflt = spec.get("default", None)
            flag = "" if name in req else "="
            args.append(f"{name}{flag}{ptype}" + (f"({dflt})" if dflt is not None else ""))
        rows.append({
            "name": t.name,
            "args": args,
            "desc": (t.description or "").strip().splitlines()[0][:120],
            "required": sorted(req),
        })
    rows.sort(key=lambda r: r["name"])
    OUT.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(len(rows), "tools ->", OUT)


asyncio.run(main())
