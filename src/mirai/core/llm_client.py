"""Client LLM double-mode : tool calling OpenAI natif ou repli JSON parsé.

Une seule représentation interne (ToolCall) quel que soit le fil. Mode résolu
depuis la config `llm_tool_mode` ("auto" par défaut, distribuable par DM) ;
en auto, une erreur HTTP 400/404/422 sur une requête portant des tools bascule
définitivement en "json" (caché dans `llm_tool_mode_detected`).

Règle de streaming en mode JSON : les deltas sont retenus tant que la réponse
peut être un appel d'outil (commence par '{', '```' ou '<think>') ; si le
parse échoue en fin de stream, le texte est restitué intégralement — on ne
perd JAMAIS la sortie du modèle.
"""

import dataclasses
import json
import re

from . import sse_pump
from .tool_calls import ToolCall
from .text_filters import strip_think_blocks

DEFAULT_STEP_MAX_TOKENS = 4000

_FENCE_RE = re.compile(r"```[a-zA-Z]*\n?|```")


@dataclasses.dataclass
class StepResult:
    text: str = ""
    tool_calls: list = dataclasses.field(default_factory=list)
    finish_reason: str = ""
    streamed: bool = False    # True si le texte a déjà été poussé au sink
    error: str = ""           # "http_429", "network_error"… — étape interrompue
    raw_json: str = ""        # réponse JSON brute (mode json, ré-encodage fidèle)


def repair_json(text):
    """Réparations minimales pour le JSON de petits modèles."""
    text = text.replace("“", '"').replace("”", '"')
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


def _first_balanced_object(text):
    """Extrait le premier objet JSON {...} équilibré, en respectant les chaînes."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        start = text.find("{", start + 1)
    return ""


def parse_json_tool_calls(text):
    """Parse tolérant de la sortie JSON du protocole de repli.

    Accepte {"tool_calls":[{name, arguments}…]} ou un appel nu
    {"name": …, "arguments": …}. Retourne [] si ce n'est pas un appel d'outil.
    """
    cleaned = strip_think_blocks(text or "")
    cleaned = _FENCE_RE.sub("", cleaned).strip()
    candidate = _first_balanced_object(cleaned)
    if not candidate:
        return []
    try:
        data = json.loads(repair_json(candidate))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []

    entries = None
    if isinstance(data.get("tool_calls"), list):
        entries = data["tool_calls"]
    elif "name" in data and "arguments" in data:
        entries = [data]
    if not entries:
        return []

    calls = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        arguments = entry.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(repair_json(arguments))
            except Exception:
                arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        calls.append(ToolCall(id=f"call_{i}", name=name, arguments=arguments,
                              raw=candidate))
    return calls


class LLMClient:
    def __init__(self, shell, max_tokens=None):
        self.shell = shell
        try:
            self.max_tokens = int(max_tokens or shell.get_config(
                "assistant_max_tokens", DEFAULT_STEP_MAX_TOKENS))
        except Exception:
            self.max_tokens = DEFAULT_STEP_MAX_TOKENS
        self.configured_mode = str(
            shell.get_config("llm_tool_mode", "auto") or "auto").strip().lower()
        if self.configured_mode not in ("auto", "native", "json"):
            self.configured_mode = "auto"

    def effective_mode(self):
        if self.configured_mode != "auto":
            return self.configured_mode
        detected = str(self.shell.get_config("llm_tool_mode_detected", "") or "")
        return "json" if detected == "json" else "native"

    def step(self, messages, tools=None, on_text_delta=None):
        """Un aller LLM. Avec `tools`, peut retourner des tool_calls ;
        sans tools, streaming texte intégral (aucune rétention)."""
        mode = self.effective_mode() if tools else "text"
        result = self._run_step(messages, tools, on_text_delta, mode)

        # Auto-détection : le relais rejette la requête portant des tools →
        # bascule définitive en mode JSON et re-tentative immédiate.
        if (result.error in ("http_400", "http_404", "http_422")
                and mode == "native" and self.configured_mode == "auto"):
            self.shell.log("[llm] tools natifs rejetés — bascule en mode json")
            try:
                self.shell.set_config("llm_tool_mode_detected", "json")
            except Exception:
                pass
            result = self._run_step(messages, tools, on_text_delta, "json")
        return result

    def _run_step(self, messages, tools, on_text_delta, mode):
        extra_body = None
        if tools and mode == "native":
            extra_body = {"tools": tools, "tool_choice": "auto"}

        # Fabrique différée : build_chat_request lit la config et peut résoudre
        # le modèle via le réseau. Exécutée dans le thread du pump, jamais sur
        # le thread principal — sinon LibreOffice paraît gelé (cf. sse_pump).
        def _build_request():
            return self.shell.build_chat_request(
                messages, max_tokens=self.max_tokens, extra_body=extra_body)

        text_parts = []
        withhold = (mode == "json")   # rétention tant que ça ressemble à un tool call
        decided = [False]
        live = [False]
        fragments = {}                # index → {id, name, arguments}
        finish = [""]

        def _handle_text(content):
            text_parts.append(content)
            if on_text_delta is None:
                return
            if not withhold:
                live[0] = True
                on_text_delta(content)
                return
            if live[0]:
                on_text_delta(content)
                return
            if not decided[0]:
                accumulated = "".join(text_parts).lstrip()
                if not accumulated:
                    return
                if accumulated[0] in "{`<":
                    decided[0] = True      # candidat tool call / think : on retient
                else:
                    decided[0] = True
                    live[0] = True
                    on_text_delta("".join(text_parts))

        def _on_event(event):
            chunk = event.chunk
            choices = chunk.get("choices") or []
            if not choices:
                return
            choice = choices[0]
            delta = choice.get("delta") or {}
            for fragment in delta.get("tool_calls") or []:
                index = int(fragment.get("index", 0))
                slot = fragments.setdefault(
                    index, {"id": "", "name": "", "arguments": ""})
                if fragment.get("id"):
                    slot["id"] = fragment["id"]
                function = fragment.get("function") or {}
                if function.get("name"):
                    slot["name"] += function["name"]
                if function.get("arguments"):
                    slot["arguments"] += function["arguments"]
            content = delta.get("content")
            if content:
                _handle_text(content)
            if choice.get("finish_reason"):
                finish[0] = choice["finish_reason"]

        outcome = sse_pump.run_stream(self.shell, _build_request, _on_event)
        if not outcome.ok:
            if isinstance(outcome.error, sse_pump.StreamHttpError):
                return StepResult(error=f"http_{outcome.error.status}",
                                  finish_reason=finish[0])
            return StepResult(error="network_error", finish_reason=finish[0])

        full_text = "".join(text_parts)

        if fragments:  # mode natif : tool calls assemblés
            calls = []
            for index in sorted(fragments):
                slot = fragments[index]
                try:
                    arguments = json.loads(repair_json(slot["arguments"] or "{}"))
                except Exception:
                    arguments = {}
                if not isinstance(arguments, dict):
                    arguments = {}
                calls.append(ToolCall(
                    id=slot["id"] or f"call_{index}", name=slot["name"],
                    arguments=arguments, raw=slot["arguments"]))
            return StepResult(text=full_text, tool_calls=calls,
                              finish_reason=finish[0], streamed=live[0])

        if mode == "json" and tools:
            calls = parse_json_tool_calls(full_text)
            if calls:
                return StepResult(tool_calls=calls, finish_reason=finish[0],
                                  raw_json=calls[0].raw)
            # Pas un tool call : texte final — jamais perdu même s'il était retenu
            clean = strip_think_blocks(full_text)
            return StepResult(text=clean, finish_reason=finish[0], streamed=live[0])

        return StepResult(text=strip_think_blocks(full_text),
                          finish_reason=finish[0], streamed=live[0])

    def encode_tool_exchange(self, step, results):
        """Ré-encode l'échange (appel + résultats) dans le format du fil actif."""
        if step.raw_json:  # mode json
            payload = [
                {"name": (step.tool_calls[i].name if i < len(step.tool_calls) else ""),
                 "ok": r.ok,
                 "result": r.content if r.ok else r.error}
                for i, r in enumerate(results)
            ]
            return [
                {"role": "assistant", "content": step.raw_json},
                {"role": "user", "content":
                    "RÉSULTATS DES OUTILS :\n"
                    + json.dumps(payload, ensure_ascii=False)
                    + "\nPoursuis la tâche. Si elle est terminée, réponds "
                      "normalement (sans JSON)."},
            ]
        # mode natif
        assistant_message = {
            "role": "assistant",
            "content": step.text or None,
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.name,
                              "arguments": json.dumps(tc.arguments, ensure_ascii=False)}}
                for tc in step.tool_calls
            ],
        }
        tool_messages = [
            {"role": "tool", "tool_call_id": r.call_id,
             "content": r.content if r.ok else f"ERREUR : {r.error}"}
            for r in results
        ]
        return [assistant_message] + tool_messages
