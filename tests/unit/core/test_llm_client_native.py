"""Client LLM : assemblage natif fragmenté, rétention JSON, détection auto."""

import io
import urllib.error

from src.mirai.core.llm_client import LLMClient
from tests.stubs.fake_shell import (
    FakeShell, FakeSSEResponse, native_tool_call_chunks, text_chunks,
)

TOOLS = [{"type": "function",
          "function": {"name": "writer_get_selection",
                       "description": "d", "parameters": {"type": "object",
                                                          "properties": {}}}}]


def test_text_only_streams_live():
    shell = FakeShell(responses=[FakeSSEResponse(text_chunks("Bon", "jour"))])
    client = LLMClient(shell)
    deltas = []
    step = client.step([{"role": "user", "content": "salut"}],
                       on_text_delta=deltas.append)
    assert step.text == "Bonjour"
    assert step.streamed and deltas == ["Bon", "jour"]
    assert step.tool_calls == []


def test_native_fragmented_tool_call_assembled():
    shell = FakeShell(
        config={"llm_tool_mode": "native"},
        responses=[FakeSSEResponse(
            native_tool_call_chunks("calc_read_range", '{"range": "A1:B2"}'))])
    client = LLMClient(shell)
    step = client.step([{"role": "user", "content": "lis"}], tools=TOOLS)
    assert len(step.tool_calls) == 1
    call = step.tool_calls[0]
    assert call.name == "calc_read_range"
    assert call.arguments == {"range": "A1:B2"}
    assert call.id == "call_abc"
    assert step.finish_reason == "tool_calls"
    # la requête portait bien les tools
    assert shell.requests[0].get("tools") == TOOLS


def test_json_mode_no_tools_in_body():
    shell = FakeShell(
        config={"llm_tool_mode": "json"},
        responses=[FakeSSEResponse(text_chunks(
            '{"tool_calls": [{"name": "writer_get_selection", "arguments": {}}]}'))])
    client = LLMClient(shell)
    step = client.step([{"role": "user", "content": "x"}], tools=TOOLS)
    assert "tools" not in shell.requests[0]
    assert len(step.tool_calls) == 1
    assert step.raw_json


def test_json_mode_withholds_tool_call_from_sink():
    shell = FakeShell(
        config={"llm_tool_mode": "json"},
        responses=[FakeSSEResponse(text_chunks(
            '{"tool_calls": [{"na', 'me": "writer_get_selection", "arguments": {}}]}'))])
    client = LLMClient(shell)
    deltas = []
    step = client.step([{"role": "user", "content": "x"}], tools=TOOLS,
                       on_text_delta=deltas.append)
    assert deltas == []                 # rien n'a fui vers le document
    assert len(step.tool_calls) == 1


def test_json_mode_streams_plain_answer_live():
    shell = FakeShell(
        config={"llm_tool_mode": "json"},
        responses=[FakeSSEResponse(text_chunks("Voici ", "la réponse."))])
    client = LLMClient(shell)
    deltas = []
    step = client.step([{"role": "user", "content": "x"}], tools=TOOLS,
                       on_text_delta=deltas.append)
    assert step.text == "Voici la réponse."
    assert step.streamed
    assert "".join(deltas) == "Voici la réponse."


def test_json_mode_withheld_non_json_never_lost():
    # Commence par '{' mais n'est pas un tool call → texte restitué à la fin.
    shell = FakeShell(
        config={"llm_tool_mode": "json"},
        responses=[FakeSSEResponse(text_chunks('{"resultat"', ': "pas un tool"}'))])
    client = LLMClient(shell)
    deltas = []
    step = client.step([{"role": "user", "content": "x"}], tools=TOOLS,
                       on_text_delta=deltas.append)
    assert step.tool_calls == []
    assert step.text == '{"resultat": "pas un tool"}'
    assert not step.streamed            # le sink le recevra via finish()


def test_auto_mode_flips_to_json_on_http_400():
    error = urllib.error.HTTPError("http://fake", 400, "bad",
                                   {}, io.BytesIO(b'{"error":"tools"}'))
    shell = FakeShell(
        config={"llm_tool_mode": "auto"},
        responses=[error, FakeSSEResponse(text_chunks("ok sans tools"))])
    client = LLMClient(shell)
    step = client.step([{"role": "user", "content": "x"}], tools=TOOLS)
    assert shell.config.get("llm_tool_mode_detected") == "json"
    assert step.text == "ok sans tools"
    assert "tools" in shell.requests[0]      # 1er essai natif
    assert "tools" not in shell.requests[1]  # retry JSON


def test_http_error_returned_as_step_error():
    error = urllib.error.HTTPError("http://fake", 429, "quota",
                                   {}, io.BytesIO(b"{}"))
    shell = FakeShell(config={"llm_tool_mode": "native"}, responses=[error])
    client = LLMClient(shell)
    step = client.step([{"role": "user", "content": "x"}], tools=TOOLS)
    assert step.error == "http_429"


def test_network_error_returned_as_step_error():
    shell = FakeShell(responses=[OSError("timed out")])
    client = LLMClient(shell)
    step = client.step([{"role": "user", "content": "x"}])
    assert step.error == "network_error"


def test_encode_tool_exchange_native():
    from src.mirai.core.tool_calls import ToolCall, ToolResult
    client = LLMClient(FakeShell(config={"llm_tool_mode": "native"}))
    from src.mirai.core.llm_client import StepResult
    step = StepResult(tool_calls=[ToolCall(id="c1", name="t", arguments={"a": 1})])
    results = [ToolResult(call_id="c1", ok=True, content="résultat")]
    messages = client.encode_tool_exchange(step, results)
    assert messages[0]["role"] == "assistant"
    assert messages[0]["tool_calls"][0]["id"] == "c1"
    assert messages[1] == {"role": "tool", "tool_call_id": "c1",
                           "content": "résultat"}


def test_encode_tool_exchange_json():
    from src.mirai.core.tool_calls import ToolCall, ToolResult
    from src.mirai.core.llm_client import StepResult
    client = LLMClient(FakeShell(config={"llm_tool_mode": "json"}))
    raw = '{"tool_calls": [{"name": "t", "arguments": {}}]}'
    step = StepResult(tool_calls=[ToolCall(id="call_0", name="t", arguments={})],
                      raw_json=raw)
    results = [ToolResult(call_id="call_0", ok=False, content="", error="cassé")]
    messages = client.encode_tool_exchange(step, results)
    assert messages[0] == {"role": "assistant", "content": raw}
    assert "RÉSULTATS DES OUTILS" in messages[1]["content"]
    assert "cassé" in messages[1]["content"]
