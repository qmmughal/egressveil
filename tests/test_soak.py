"""Soak test: long streams through the gateway keep memory flat and bytes intact."""

from __future__ import annotations

import asyncio
import hashlib
import sys
import tracemalloc
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import perf


def test_long_stream_memory_is_bounded_and_bytes_intact(tmp_path: Path) -> None:
    async def scenario() -> tuple[str, str, int]:
        up_port = perf.free_port()
        up = await perf.start(perf.upstream_app(stream_mb=24), up_port)
        gw, port = await perf.gateway(up_port, True, tmp_path / "audit.jsonl")
        try:
            async with aiohttp.ClientSession(auto_decompress=False) as s:
                direct = hashlib.sha256()
                async with s.get(f"http://127.0.0.1:{up_port}/v1/stream") as r:
                    async for chunk in r.content.iter_chunked(perf.CHUNK):
                        direct.update(chunk)
                tracemalloc.start()
                via = hashlib.sha256()
                async with s.get(f"http://127.0.0.1:{port}/v1/stream") as r:
                    async for chunk in r.content.iter_chunked(perf.CHUNK):
                        via.update(chunk)
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
            return direct.hexdigest(), via.hexdigest(), peak
        finally:
            await gw.cleanup()
            await up.cleanup()

    direct, via, peak = asyncio.run(scenario())
    assert via == direct  # response bytes are never modified
    assert peak < 16 * 1024 * 1024, f"peak {peak / 1e6:.1f} MB for a 24 MB stream"
