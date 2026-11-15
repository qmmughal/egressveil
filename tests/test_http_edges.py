"""Raw-socket HTTP edge cases: smuggling, malformed framing, oversized headers.

Each case sends bytes a normal client never would and checks that the gateway
rejects them (or handles them safely) and that nothing unintended reaches the
upstream.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from tests import fakes
from tests.helpers import messages_body
from tests.test_gateway import stack

CLEAN = json.dumps(messages_body("hello")).encode()
SECRET = json.dumps(messages_body(f"use {fakes.github_token()}")).encode()


def http(
    host: str,
    *headers: str,
    body: bytes = b"",
    target: str = "/v1/messages",
    version: str = "HTTP/1.1",
) -> bytes:
    lines = [f"POST {target} {version}", *([f"Host: {host}"] if host else []), *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


async def raw_exchange(port: int, payload: bytes, timeout: float = 5.0) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    chunks = b""
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout)
            if not data:
                break
            chunks += data
    except TimeoutError:
        pass
    finally:
        writer.close()
    return chunks


def statuses(response: bytes) -> list[int]:
    # Pipelined responses follow each other directly, without a line break.
    return [int(m) for m in re.findall(rb"HTTP/1\.[01] (\d{3}) ", response)]


async def run_case(tmp_path: Path, build: object) -> tuple[list[int], int]:
    async with stack(tmp_path) as (base, up):
        port = int(base.rsplit(":", 1)[1])
        host = f"127.0.0.1:{port}"
        payload = build(host)  # type: ignore[operator]
        response = await raw_exchange(port, payload, timeout=2.0)
        return statuses(response), len(up.requests)


CASES = {
    "content-length and transfer-encoding (CL.TE smuggling)": lambda h: http(
        h,
        "Content-Type: application/json",
        f"Content-Length: {len(CLEAN)}",
        "Transfer-Encoding: chunked",
        body=CLEAN,
    ),
    "conflicting duplicate content-length": lambda h: http(
        h,
        "Content-Type: application/json",
        f"Content-Length: {len(CLEAN)}",
        "Content-Length: 5",
        body=CLEAN,
    ),
    "invalid chunk size": lambda h: http(
        h,
        "Content-Type: application/json",
        "Transfer-Encoding: chunked",
        body=b"zz\r\n" + CLEAN + b"\r\n0\r\n\r\n",
    ),
    "oversized header line": lambda h: http(
        h,
        "Content-Type: application/json",
        "X-Big: " + "a" * 20000,
        f"Content-Length: {len(CLEAN)}",
        body=CLEAN,
    ),
    "transfer-encoding other than chunked": lambda h: http(
        h, "Content-Type: application/json", "Transfer-Encoding: gzip, identity", body=CLEAN
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_malformed_framing_is_rejected_and_not_forwarded(tmp_path: Path, name: str) -> None:
    codes, forwarded = asyncio.run(run_case(tmp_path, CASES[name]))
    assert forwarded == 0, f"{name}: request reached the upstream"
    assert codes and all(400 <= c < 500 for c in codes), codes


def test_http10_without_host_is_refused(tmp_path: Path) -> None:
    def build(_host: str) -> bytes:
        return http(
            "",
            "Content-Type: application/json",
            f"Content-Length: {len(CLEAN)}",
            body=CLEAN,
            version="HTTP/1.0",
        )

    codes, forwarded = asyncio.run(run_case(tmp_path, build))
    assert codes == [403]
    assert forwarded == 0


def test_absolute_form_target_cannot_redirect_upstream(tmp_path: Path) -> None:
    def build(host: str) -> bytes:
        return http(
            host,
            "Content-Type: application/json",
            f"Content-Length: {len(CLEAN)}",
            "Connection: close",
            body=CLEAN,
            target="http://evil.example/v1/messages",
        )

    async def scenario() -> tuple[list[int], list[str]]:
        async with stack(tmp_path) as (base, up):
            port = int(base.rsplit(":", 1)[1])
            response = await raw_exchange(port, build(f"127.0.0.1:{port}"))
            return statuses(response), [r["path_qs"] for r in up.requests]

    codes, paths = asyncio.run(scenario())
    # Forwarded to the configured upstream with exactly the inspected path.
    assert codes == [200]
    assert paths == ["/v1/messages"]


@pytest.mark.parametrize(
    "target",
    ["/openai%2Fv1/chat/completions", "/v1%2Fmessages", "/v1/messages/%2e%2e/files"],
)
def test_encoded_path_tricks_are_refused(tmp_path: Path, target: str) -> None:
    def build(host: str) -> bytes:
        return http(
            host,
            "Content-Type: application/json",
            f"Content-Length: {len(CLEAN)}",
            "Connection: close",
            body=CLEAN,
            target=target,
        )

    codes, forwarded = asyncio.run(run_case(tmp_path, build))
    assert forwarded == 0
    assert codes and all(400 <= c < 500 for c in codes)


def test_pipelined_requests_are_each_inspected(tmp_path: Path) -> None:
    def build(host: str) -> bytes:
        first = http(
            host, "Content-Type: application/json", f"Content-Length: {len(CLEAN)}", body=CLEAN
        )
        second = http(
            host,
            "Content-Type: application/json",
            f"Content-Length: {len(SECRET)}",
            "Connection: close",
            body=SECRET,
        )
        return first + second

    codes, forwarded = asyncio.run(run_case(tmp_path, build))
    assert codes == [200, 400]  # clean one forwarded, the one with a token blocked
    assert forwarded == 1


def test_body_shorter_than_content_length_is_not_forwarded(tmp_path: Path) -> None:
    def build(host: str) -> bytes:
        return http(
            host, "Content-Type: application/json", f"Content-Length: {len(CLEAN) + 50}", body=CLEAN
        )

    codes, forwarded = asyncio.run(run_case(tmp_path, build))
    assert forwarded == 0
    assert all(c >= 400 for c in codes)
