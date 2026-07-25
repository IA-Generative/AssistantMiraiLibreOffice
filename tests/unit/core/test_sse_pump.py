"""Pump SSE : ordre des événements, [DONE], erreurs HTTP/réseau → coquille."""

import io
import urllib.error

from src.mirai.core import sse_pump
from tests.stubs.fake_shell import FakeShell, FakeSSEResponse, text_chunks


def _http_error(status, body=b'{"error":{"code":"quota"}}'):
    return urllib.error.HTTPError(
        "http://fake", status, "err", {"X-Request-Id": "req-1"}, io.BytesIO(body))


def test_chunks_delivered_in_order():
    shell = FakeShell(responses=[FakeSSEResponse(text_chunks("a", "b", "c"))])
    seen = []
    outcome = sse_pump.run_stream(shell, object(), lambda e: seen.append(e.chunk))
    assert outcome.ok
    contents = [c["choices"][0]["delta"].get("content") for c in seen]
    assert contents[:3] == ["a", "b", "c"]


def test_done_terminates_stream():
    lines = [b"data: " + b'{"choices":[{"delta":{"content":"x"}}]}',
             b"data: [DONE]",
             b"data: " + b'{"choices":[{"delta":{"content":"jamais"}}]}']
    shell = FakeShell(responses=[FakeSSEResponse(None, raw_lines=lines)])
    seen = []
    sse_pump.run_stream(shell, object(), lambda e: seen.append(e.chunk))
    assert len(seen) == 1


def test_invalid_json_lines_skipped():
    lines = [b"data: {pas du json", b'data: {"choices":[{"delta":{"content":"ok"}}]}',
             b"data: [DONE]"]
    shell = FakeShell(responses=[FakeSSEResponse(None, raw_lines=lines)])
    seen = []
    outcome = sse_pump.run_stream(shell, object(), lambda e: seen.append(e))
    assert outcome.ok and len(seen) == 1


def test_http_error_reported_to_shell():
    shell = FakeShell(responses=[_http_error(429)])
    outcome = sse_pump.run_stream(shell, object(), lambda e: None)
    assert not outcome.ok
    assert isinstance(outcome.error, sse_pump.StreamHttpError)
    assert outcome.error.status == 429
    assert shell.llm_errors and shell.llm_errors[0][0] == 429


def test_network_error_reported_to_shell():
    shell = FakeShell(responses=[OSError("connexion timed out")])
    outcome = sse_pump.run_stream(shell, object(), lambda e: None)
    assert not outcome.ok
    assert isinstance(outcome.error, sse_pump.StreamNetworkError)
    assert shell.llm_errors and shell.llm_errors[0][0] == 0


def test_on_event_exception_does_not_break_stream():
    shell = FakeShell(responses=[FakeSSEResponse(text_chunks("a", "b"))])
    calls = []

    def _handler(event):
        calls.append(event)
        raise RuntimeError("boom")

    outcome = sse_pump.run_stream(shell, object(), _handler)
    assert outcome.ok and len(calls) >= 2
