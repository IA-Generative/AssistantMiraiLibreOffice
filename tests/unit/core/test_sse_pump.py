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


def test_request_factory_is_called_lazily():
    """La requête peut être construite par un callable — exécuté dans le
    thread réseau pour ne jamais bloquer le thread principal (gel de LO)."""
    shell = FakeShell(responses=[FakeSSEResponse(text_chunks("ok"))])
    calls = []

    def _factory():
        calls.append("built")
        return object()

    outcome = sse_pump.run_stream(shell, _factory, lambda e: None)
    assert outcome.ok
    assert calls == ["built"]


def test_request_factory_failure_becomes_network_error():
    shell = FakeShell()

    def _factory():
        raise RuntimeError("résolution du modèle impossible")

    outcome = sse_pump.run_stream(shell, _factory, lambda e: None)
    assert not outcome.ok
    assert isinstance(outcome.error, sse_pump.StreamNetworkError)
    assert shell.llm_errors and shell.llm_errors[0][0] == 0


def test_llm_client_does_not_build_request_on_calling_thread():
    """Garde-fou anti-régression : LLMClient.step ne doit pas appeler
    build_chat_request avant de lancer le pump."""
    import threading
    from src.mirai.core.llm_client import LLMClient

    main_thread = threading.current_thread().ident
    build_threads = []

    class _RecordingShell(FakeShell):
        def build_chat_request(self, messages, max_tokens=2000, extra_body=None):
            build_threads.append(threading.current_thread().ident)
            return super().build_chat_request(messages, max_tokens, extra_body)

    shell = _RecordingShell(responses=[FakeSSEResponse(text_chunks("ok"))])
    LLMClient(shell).step([{"role": "user", "content": "x"}])
    assert build_threads and all(t != main_thread for t in build_threads), (
        "build_chat_request doit s'exécuter hors du thread appelant")


def test_on_event_exception_does_not_break_stream():
    shell = FakeShell(responses=[FakeSSEResponse(text_chunks("a", "b"))])
    calls = []

    def _handler(event):
        calls.append(event)
        raise RuntimeError("boom")

    outcome = sse_pump.run_stream(shell, object(), _handler)
    assert outcome.ok and len(calls) >= 2
