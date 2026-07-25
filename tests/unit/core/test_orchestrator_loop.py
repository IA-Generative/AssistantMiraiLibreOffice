"""Boucle agentique : run texte, run avec tools, plafond d'itérations, undo,
conversation, observer (journal d'actions), erreurs HTTP."""

import dataclasses
import tempfile

from src.mirai.core.conversation import ConversationStore
from src.mirai.core.llm_client import StepResult
from src.mirai.core.orchestrator import Orchestrator, RunObserver
from src.mirai.core.registry import ToolRegistry
from src.mirai.core.sinks import PaletteSink
from src.mirai.core.tool_calls import ToolCall, ToolResult, ToolSpec
from tests.stubs.fake_shell import FakeShell


class FakeLLM:
    configured_mode = "native"

    def __init__(self, steps):
        self._steps = list(steps)
        self.seen_messages = []

    def effective_mode(self):
        return "native"

    def step(self, messages, tools=None, on_text_delta=None):
        self.seen_messages.append(list(messages))
        step = self._steps.pop(0)
        if step.text and not step.tool_calls and on_text_delta:
            on_text_delta(step.text)
            step.streamed = True
        return step

    def encode_tool_exchange(self, step, results):
        return [{"role": "assistant", "content": "<tool-exchange>"}]


class _Ctx:
    def __init__(self, shell, app="writer"):
        self.app = app
        self.shell = shell
        self.undo_begun = []
        self.undo_ended = 0
        self.uno_ctx = None
        self.model = None
        self.controller = None

    def undo_begin(self, label):
        self.undo_begun.append(label)

    def undo_end(self):
        self.undo_ended += 1


class _RecordingObserver(RunObserver):
    def __init__(self):
        self.events = []

    def on_run_start(self, mode):
        self.events.append(("start", mode))

    def on_tool_calls(self, calls):
        self.events.append(("proposed", [c.name for c in calls]))

    def on_tool_result(self, call, result, duration_ms):
        self.events.append(("result", call.name, result.ok))

    def on_final(self, text):
        self.events.append(("final", text))

    def on_error(self, code, message):
        self.events.append(("error", code))


def _registry():
    registry = ToolRegistry()
    registry.register(ToolSpec(
        name="writer_probe", description="sonde",
        parameters={"type": "object", "properties": {}},
        handler=lambda ctx, args: ToolResult(call_id="", ok=True, content="vu"),
        apps=("writer",),
    ))
    return registry


def test_text_only_run():
    shell = FakeShell()
    ctx = _Ctx(shell)
    observer = _RecordingObserver()
    sink = PaletteSink()
    orchestrator = Orchestrator(FakeLLM([StepResult(text="Réponse.")]),
                                _registry(), ctx, observer=observer)
    result = orchestrator.run_agentic("question", sink)
    assert result.ok and result.iterations == 1
    assert sink.text == "Réponse."
    assert ("final", "Réponse.") in observer.events
    assert ctx.undo_ended == 1
    spans = [s for s, _ in shell.telemetry_events]
    assert "AssistantRun" in spans


def test_tool_call_then_final():
    shell = FakeShell()
    ctx = _Ctx(shell)
    observer = _RecordingObserver()
    llm = FakeLLM([
        StepResult(tool_calls=[ToolCall(id="c1", name="writer_probe", arguments={})]),
        StepResult(text="Fini."),
    ])
    orchestrator = Orchestrator(llm, _registry(), ctx, observer=observer)
    result = orchestrator.run_agentic("fais un truc", PaletteSink())
    assert result.ok and result.iterations == 2
    assert ("proposed", ["writer_probe"]) in observer.events
    assert ("result", "writer_probe", True) in observer.events
    # l'échange outil a été réinjecté dans les messages du 2e step
    assert any(m.get("content") == "<tool-exchange>"
               for m in llm.seen_messages[1])


def test_max_iterations_terminates():
    shell = FakeShell()
    ctx = _Ctx(shell)
    observer = _RecordingObserver()
    endless = [StepResult(tool_calls=[ToolCall(id=f"c{i}", name="writer_probe",
                                               arguments={})])
               for i in range(10)]
    orchestrator = Orchestrator(FakeLLM(endless), _registry(), ctx,
                                observer=observer, max_iterations=3)
    result = orchestrator.run_agentic("boucle", PaletteSink())
    assert not result.ok and result.reason == "max_iterations"
    assert ("error", "max_iterations") in observer.events
    assert ctx.undo_ended == 1


def test_step_error_stops_run_with_message():
    shell = FakeShell()
    ctx = _Ctx(shell)
    observer = _RecordingObserver()
    orchestrator = Orchestrator(FakeLLM([StepResult(error="http_429")]),
                                _registry(), ctx, observer=observer)
    result = orchestrator.run_agentic("x", PaletteSink())
    assert not result.ok and result.reason == "http_429"
    assert "Quota" in result.text
    assert ("error", "http_429") in observer.events


def test_conversation_recorded_and_injected():
    shell = FakeShell()
    ctx = _Ctx(shell)
    store = ConversationStore(tempfile.mkdtemp())
    store.append("user", "question précédente")
    store.append("assistant", "réponse précédente")
    llm = FakeLLM([StepResult(text="Nouvelle réponse.")])
    orchestrator = Orchestrator(llm, _registry(), ctx, conversation=store)
    orchestrator.run_agentic("nouvelle question", PaletteSink())
    # contexte injecté
    first_messages = llm.seen_messages[0]
    contents = [m["content"] for m in first_messages]
    assert "réponse précédente" in contents
    # tour enregistré
    entries = store.load()
    assert entries[-1]["text"] == "Nouvelle réponse."
    assert entries[-2]["text"] == "nouvelle question"


def test_conversation_not_polluted_by_failed_run():
    shell = FakeShell()
    ctx = _Ctx(shell)
    store = ConversationStore(tempfile.mkdtemp())
    orchestrator = Orchestrator(FakeLLM([StepResult(error="network_error")]),
                                _registry(), ctx, conversation=store)
    orchestrator.run_agentic("x", PaletteSink())
    assert store.load() == []
