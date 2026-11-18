"""Command line entry point.

    python -m tiscan                      start the dashboard (http://127.0.0.1:8787)
    python -m tiscan scan 8.8.8.8         scan one indicator in the terminal
    python -m tiscan scan evil.com --mode full --json
    python -m tiscan extract mail.eml     list the IOCs found in a file (or stdin)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import sys
import threading
import webbrowser

from . import __version__
from .config import settings

COLORS = {"malicious": "91", "critical": "91", "high": "91", "suspicious": "93", "medium": "93",
          "low": "96", "clean": "92", "info": "94", "unknown": "90"}


def _c(text: str, key: str) -> str:
    if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        return text
    return f"\033[{COLORS.get(key, '0')}m{text}\033[0m"


def _free_port(host: str, port: int, attempts: int = 20) -> int:
    """First free port starting at `port` (Splunk, Burp etc. often hold the usual ones)."""
    for candidate in range(port, port + attempts):
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, candidate))
                return candidate
            except OSError:
                continue
    raise SystemExit(f"No free port between {port} and {port + attempts - 1} - set TISCAN_PORT in .env")


def serve(host: str, port: int, open_browser: bool) -> None:
    import uvicorn

    chosen = _free_port(host, port)
    if chosen != port:
        print(f"  Port {port} is in use by another program - using {chosen} instead.")
    port = chosen
    # Keep the real address in settings so report links in alerts are correct.
    os.environ["TISCAN_HOST"], os.environ["TISCAN_PORT"] = host, str(port)
    settings.reload()
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}"
    print(f"\n  TIScan {__version__} - dashboard on {url}\n  Press Ctrl+C to stop.\n")
    if open_browser:
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    uvicorn.run("tiscan.app:app", host=host, port=port, log_level="warning")


async def scan(value: str, mode: str, as_json: bool, nocache: bool) -> int:
    import httpx

    from .db import Database
    from .engine import Engine
    from .ioc import detect

    try:
        ioc = detect(value, allow_keyword=(mode == "darkweb"))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    db = Database(settings.db_path)
    async with httpx.AsyncClient(headers={"User-Agent": settings.user_agent}, follow_redirects=True,
                                 timeout=settings.http_timeout) as client:
        report = await Engine(client, db).scan(ioc, mode=mode, nocache=nocache)
    db.close()
    if as_json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    risk, exposure = report.get("risk"), report.get("exposure")
    print(f"\n  {report['ioc']['value']}  [{report['ioc']['type']}]  ({report['duration_ms']} ms)")
    if risk:
        text = "%s/100 %s" % (risk["score"], risk["level"].upper())
        print(f"  Threat risk : {_c(text, risk['level'])}  ({risk['answered']}/{risk['total']} sources answered)")
    if exposure:
        text = "%s/100 %s" % (exposure["score"], exposure["level"].upper())
        print(f"  Dark-web    : {_c(text, exposure['level'])}")
    print()
    for r in report["results"]:
        label = r["verdict"] if r["status"] in ("ok", "not_found") else r["status"]
        print(f"  {_c(label.ljust(12), r['verdict'])} {r['name']:<34} {r['summary'][:90]}")
    if report.get("related"):
        print(f"\n  {len(report['related'])} related indicator(s) - open the dashboard to pivot.")
    print(f"\n  Saved as scan #{report.get('id')}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tiscan", description="Threat intelligence & dark-web exposure scanner")
    parser.add_argument("--version", action="version", version=f"TIScan {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="start the web dashboard (default)")
    p_serve.add_argument("--host", default=settings.host)
    p_serve.add_argument("--port", type=int, default=settings.port)
    p_serve.add_argument("--no-browser", action="store_true")

    p_scan = sub.add_parser("scan", help="scan one indicator")
    p_scan.add_argument("ioc")
    p_scan.add_argument("--mode", choices=["full", "fast", "darkweb"], default="fast")
    p_scan.add_argument("--json", action="store_true", help="print the full JSON report")
    p_scan.add_argument("--nocache", action="store_true")

    p_extract = sub.add_parser("extract", help="extract IOCs from a file or stdin")
    p_extract.add_argument("file", nargs="?")

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return asyncio.run(scan(args.ioc, args.mode, args.json, args.nocache))
    if args.cmd == "extract":
        from .ioc import extract

        text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
        for item in extract(text):
            print(f"{item['type']:<8} {item['value']}{'  (private)' if item['private'] else ''}")
        return 0
    host = getattr(args, "host", settings.host)
    port = getattr(args, "port", settings.port)
    serve(host, port, open_browser=not getattr(args, "no_browser", False) and not os.getenv("TISCAN_NO_BROWSER"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
