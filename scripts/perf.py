"""Performance and memory measurements for the gateway (in-process, loopback).

Usage:  python scripts/perf.py [--quick]

Measures, against a local mock upstream (no real API calls):
* added latency per request, for small, medium and large Messages API bodies;
* streaming throughput through the gateway, response inspection off and on;
* peak Python memory while streaming (tracemalloc), to show it stays bounded.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import statistics
import sys
import tempfile
import time
import tracemalloc
from dataclasses import replace
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from egressveil.config import parse_config  # noqa: E402
from egressveil.proxy import build_components, create_app  # noqa: E402

CHUNK = 64 * 1024
CODE = "def handler(event, context):\n    return {'status': 200, 'body': event['path']}\n"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def body_of(size: int) -> bytes:
    text = (CODE * (size // len(CODE) + 1))[:size]
    return json.dumps(
        {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": text}]}
    ).encode()


async def start(app: web.Application, port: int) -> web.AppRunner:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    return runner


def upstream_app(stream_mb: int) -> web.Application:
    sse_event = (
        b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"'
        + (b"lorem ipsum dolor sit amet " * 40)
        + b'"}}\n\n'
    )

    async def messages(request: web.Request) -> web.StreamResponse:
        await request.read()
        return web.json_response({"type": "message", "content": [{"text": "ok"}]})

    async def stream(request: web.Request) -> web.StreamResponse:
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        block = sse_event * (CHUNK // len(sse_event))
        for _ in range(stream_mb * 1024 * 1024 // len(block)):
            await resp.write(block)
        await resp.write_eof()
        return resp

    app = web.Application(client_max_size=64 * 1024 * 1024)
    app.router.add_post("/v1/messages", messages)
    app.router.add_get("/v1/stream", stream)
    return app


async def gateway(up_port: int, inspect_responses: bool, audit: Path) -> tuple[web.AppRunner, int]:
    port = free_port()
    cfg, issues = parse_config(
        {
            "gateway": {"listen_port": port, "inspect_responses": inspect_responses},
            "audit": {"path": str(audit)},
        }
    )
    assert cfg is not None, issues
    providers = dict(cfg.providers)
    providers["anthropic"] = replace(
        providers["anthropic"], upstream_url=f"http://127.0.0.1:{up_port}"
    )
    cfg = replace(cfg, providers=providers)
    runner = await start(create_app(build_components(cfg), allow_insecure_upstream=True), port)
    return runner, port


async def latency(session: aiohttp.ClientSession, url: str, body: bytes, n: int) -> list[float]:
    out = []
    for _ in range(n):
        t = time.perf_counter()
        async with session.post(url, data=body, headers={"content-type": "application/json"}) as r:
            await r.read()
            assert r.status == 200, r.status
        out.append((time.perf_counter() - t) * 1000)
    return out


async def stream_through(session: aiohttp.ClientSession, url: str) -> tuple[int, float]:
    t = time.perf_counter()
    total = 0
    async with session.get(url) as r:
        async for chunk in r.content.iter_chunked(CHUNK):
            total += len(chunk)
    return total, time.perf_counter() - t


async def run(quick: bool) -> dict[str, Any]:
    n = 20 if quick else 100
    stream_mb = 32 if quick else 128
    tmp = Path(tempfile.mkdtemp())
    up_port = free_port()
    up = await start(upstream_app(stream_mb), up_port)
    results: dict[str, Any] = {"python": sys.version.split()[0], "requests_per_size": n}
    try:
        gw, port = await gateway(up_port, False, tmp / "a.jsonl")
        gw_ri, port_ri = await gateway(up_port, True, tmp / "b.jsonl")
        async with aiohttp.ClientSession(auto_decompress=False) as s:
            sizes = {"1 KB": 1024, "100 KB": 100 * 1024, "1 MB": 1024 * 1024}
            lat: dict[str, dict[str, float]] = {}
            for label, size in sizes.items():
                body = body_of(size)
                await latency(s, f"http://127.0.0.1:{port}/v1/messages", body, 3)  # warm-up
                direct = await latency(s, f"http://127.0.0.1:{up_port}/v1/messages", body, n)
                via = await latency(s, f"http://127.0.0.1:{port}/v1/messages", body, n)
                lat[label] = {
                    "direct_p50_ms": round(statistics.median(direct), 2),
                    "gateway_p50_ms": round(statistics.median(via), 2),
                    "overhead_p50_ms": round(statistics.median(via) - statistics.median(direct), 2),
                    "gateway_p95_ms": round(sorted(via)[int(len(via) * 0.95) - 1], 2),
                }
            results["latency"] = lat

            for label, p in (("stream_inspect_off", port), ("stream_inspect_on", port_ri)):
                total, secs = await stream_through(s, f"http://127.0.0.1:{p}/v1/stream")
                results[label] = {
                    "mb": round(total / 1e6, 1),
                    "mb_per_s": round(total / 1e6 / secs, 1),
                }

            tracemalloc.start()
            await stream_through(s, f"http://127.0.0.1:{port_ri}/v1/stream")
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            results["stream_peak_python_mb"] = round(peak / 1e6, 1)
        await gw.cleanup()
        await gw_ri.cleanup()
    finally:
        await up.cleanup()
    return results


def markdown(r: dict[str, Any]) -> str:
    lines = [
        "| Request body | Direct p50 | Through gateway p50 | Added p50 | Gateway p95 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for label, v in r["latency"].items():
        lines.append(
            f"| {label} | {v['direct_p50_ms']} ms | {v['gateway_p50_ms']} ms | "
            f"**{v['overhead_p50_ms']} ms** | {v['gateway_p95_ms']} ms |"
        )
    off, on = r["stream_inspect_off"], r["stream_inspect_on"]
    lines += [
        "",
        f"- Streaming throughput: **{off['mb_per_s']} MB/s** with response inspection off, "
        f"**{on['mb_per_s']} MB/s** with it on ({off['mb']} MB stream).",
        f"- Peak Python memory while streaming {on['mb']} MB with inspection on: "
        f"**{r['stream_peak_python_mb']} MB** (bounded by the chunk size and scan window, "
        "not by the stream length).",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = asyncio.run(run(args.quick))
    print(json.dumps(results, indent=2) if args.json else markdown(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
