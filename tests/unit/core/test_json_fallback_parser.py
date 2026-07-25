"""Parseur tolérant du protocole JSON de repli — goldens vicieux."""

from src.mirai.core.llm_client import parse_json_tool_calls


def test_clean_tool_calls():
    calls = parse_json_tool_calls(
        '{"tool_calls": [{"name": "writer_get_selection", "arguments": {}}]}')
    assert len(calls) == 1
    assert calls[0].name == "writer_get_selection"
    assert calls[0].arguments == {}


def test_fenced_json():
    text = '```json\n{"tool_calls": [{"name": "calc_read_range", "arguments": {"range": "A1:B2"}}]}\n```'
    calls = parse_json_tool_calls(text)
    assert len(calls) == 1 and calls[0].arguments["range"] == "A1:B2"


def test_think_prefix_then_json():
    text = ('<think>je vais lire la sélection</think>\n'
            '{"tool_calls": [{"name": "writer_get_selection", "arguments": {}}]}')
    calls = parse_json_tool_calls(text)
    assert len(calls) == 1


def test_prose_before_json():
    text = ('Je vais utiliser un outil.\n'
            '{"tool_calls": [{"name": "writer_get_selection", "arguments": {}}]}')
    calls = parse_json_tool_calls(text)
    assert len(calls) == 1


def test_trailing_commas_repaired():
    text = '{"tool_calls": [{"name": "writer_get_selection", "arguments": {},},],}'
    calls = parse_json_tool_calls(text)
    assert len(calls) == 1


def test_smart_quotes_repaired():
    text = '{"tool_calls": [{"name": "calc_read_range", "arguments": {"range": “A1:B2”}}]}'
    calls = parse_json_tool_calls(text)
    assert len(calls) == 1


def test_bare_single_call():
    calls = parse_json_tool_calls('{"name": "writer_get_selection", "arguments": {}}')
    assert len(calls) == 1 and calls[0].name == "writer_get_selection"


def test_arguments_as_string():
    calls = parse_json_tool_calls(
        '{"tool_calls": [{"name": "calc_read_range", "arguments": "{\\"range\\": \\"A1\\"}"}]}')
    assert len(calls) == 1 and calls[0].arguments == {"range": "A1"}


def test_plain_text_returns_empty():
    assert parse_json_tool_calls("Voici le résumé demandé.") == []


def test_json_without_tool_shape_returns_empty():
    assert parse_json_tool_calls('{"resultat": "ok"}') == []


def test_multiple_calls_ordered():
    text = ('{"tool_calls": [{"name": "a_tool", "arguments": {}},'
            ' {"name": "b_tool", "arguments": {"x": 1}}]}')
    calls = parse_json_tool_calls(text)
    assert [c.name for c in calls] == ["a_tool", "b_tool"]
    assert calls[1].arguments == {"x": 1}


def test_braces_inside_strings():
    text = '{"tool_calls": [{"name": "writer_find_replace", "arguments": {"pairs": [{"find": "a {b}", "replace": "c"}]}}]}'
    calls = parse_json_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].arguments["pairs"][0]["find"] == "a {b}"


def test_empty_and_none():
    assert parse_json_tool_calls("") == []
    assert parse_json_tool_calls(None) == []
