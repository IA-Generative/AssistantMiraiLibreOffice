"""Registre de tools : list/call, inconnu, exception, undo, plafond, télémétrie."""

from types import SimpleNamespace

from src.mirai.core.registry import ToolRegistry
from src.mirai.core.tool_calls import ToolSpec, ToolResult
from tests.stubs.fake_shell import FakeShell


class _Ctx:
    def __init__(self):
        self.app = "writer"
        self.shell = FakeShell()
        self.undo_labels = []
        self.undo_ended = 0

    def undo_begin(self, label):
        self.undo_labels.append(label)

    def undo_end(self):
        self.undo_ended += 1


def _make_registry():
    registry = ToolRegistry()
    registry.register(ToolSpec(
        name="writer_echo", description="écho",
        parameters={"type": "object", "properties": {"text": {"type": "string"}},
                    "required": ["text"]},
        handler=lambda ctx, args: ToolResult(call_id="", ok=True,
                                             content="echo:" + args["text"]),
        apps=("writer",),
    ))
    registry.register(ToolSpec(
        name="writer_boom", description="explose",
        parameters={"type": "object", "properties": {}},
        handler=lambda ctx, args: (_ for _ in ()).throw(RuntimeError("kaboom")),
        apps=("writer",), mutates=True,
    ))
    registry.register(ToolSpec(
        name="calc_only", description="calc",
        parameters={"type": "object", "properties": {}},
        handler=lambda ctx, args: ToolResult(call_id="", ok=True, content="ok"),
        apps=("calc",),
    ))
    return registry


def test_list_tools_filters_by_app():
    registry = _make_registry()
    names = [s.name for s in registry.list_tools("writer")]
    assert "writer_echo" in names and "calc_only" not in names


def test_openai_tools_format():
    registry = _make_registry()
    tools = registry.openai_tools("writer")
    assert all(t["type"] == "function" for t in tools)
    assert any(t["function"]["name"] == "writer_echo" for t in tools)


def test_prompt_catalog_mentions_tools_and_types():
    registry = _make_registry()
    catalog = registry.prompt_catalog("writer")
    assert "writer_echo" in catalog and "text: string" in catalog


def test_call_tool_success_and_telemetry():
    registry, ctx = _make_registry(), _Ctx()
    result = registry.call_tool("writer_echo", {"text": "hé"}, ctx, call_id="c1")
    assert result.ok and result.content == "echo:hé" and result.call_id == "c1"
    spans = [s for s, _ in ctx.shell.telemetry_events]
    assert "AssistantToolCall" in spans
    attrs = ctx.shell.telemetry_events[0][1]
    assert attrs["tool.name"] == "writer_echo" and attrs["tool.ok"] == "true"
    # Jamais d'arguments ni de contenu en télémétrie
    assert "hé" not in str(attrs)


def test_call_unknown_tool():
    registry, ctx = _make_registry(), _Ctx()
    result = registry.call_tool("inexistant", {}, ctx)
    assert not result.ok and "inconnu" in result.error.lower()


def test_wrong_app_tool_is_unknown():
    registry, ctx = _make_registry(), _Ctx()
    result = registry.call_tool("calc_only", {}, ctx)
    assert not result.ok


def test_validation_error_reported():
    registry, ctx = _make_registry(), _Ctx()
    result = registry.call_tool("writer_echo", {}, ctx)
    assert not result.ok and "text" in result.error


def test_handler_exception_never_raises():
    registry, ctx = _make_registry(), _Ctx()
    result = registry.call_tool("writer_boom", {}, ctx)
    assert not result.ok and "kaboom" in result.error


def test_undo_opened_only_for_mutating_tools():
    registry, ctx = _make_registry(), _Ctx()
    registry.call_tool("writer_echo", {"text": "x"}, ctx)
    assert ctx.undo_labels == []
    registry.call_tool("writer_boom", {}, ctx)
    assert len(ctx.undo_labels) == 1


def test_content_capped():
    registry, ctx = _make_registry(), _Ctx()
    ctx.shell.config["tool_result_max_chars"] = 10
    result = registry.call_tool("writer_echo", {"text": "a" * 100}, ctx)
    assert len(result.content) < 50 and "tronqué" in result.content
