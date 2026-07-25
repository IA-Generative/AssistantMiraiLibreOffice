"""Boucle agentique : prompt → LLM → tool calls → résultats → … → réponse finale.

Un run = un contexte undo (via ToolContext, ouvert par le premier tool mutant)
= un seul Ctrl+Z. Le RunObserver alimente le journal d'actions de la palette
(séquence proposée puis exécutée, façon agent). Aucun contenu de document ni
de prompt ne part en télémétrie — uniquement compteurs et statuts.
"""

import dataclasses
import time

from . import prompts


class RunObserver:
    """Interface du journal d'actions — implémentée par la palette."""

    def on_run_start(self, mode):
        pass

    def on_tool_calls(self, calls):
        pass

    def on_tool_result(self, call, result, duration_ms):
        pass

    def on_final(self, text):
        pass

    def on_error(self, code, message):
        pass


@dataclasses.dataclass
class RunResult:
    ok: bool
    iterations: int = 0
    text: str = ""
    reason: str = ""


ERROR_MESSAGES = {
    # Le renouvellement automatique du jeton (refresh /config, puis
    # ré-enrôlement) a déjà été tenté avant d'en arriver là : ce message ne
    # s'affiche que si le poste n'a pas pu se ré-authentifier tout seul.
    "http_401": ("Votre poste n'est pas authentifié auprès du service IA. "
                 "Ouvrez les Réglages pour vous reconnecter."),
    "http_403": ("Accès refusé par le relais — la configuration se "
                 "resynchronise. Réessayez dans quelques instants."),
    "http_429": ("Quota de requêtes atteint. Merci de réessayer dans "
                 "quelques instants."),
    "network_error": ("Le serveur IA est injoignable. Vérifiez votre "
                      "connexion réseau puis réessayez."),
}


def error_message(code):
    return ERROR_MESSAGES.get(code, f"Erreur du service IA ({code}). Réessayez.")


DEFAULT_MAX_ITERATIONS = 6


class Orchestrator:
    def __init__(self, llm, registry, ctx, observer=None, conversation=None,
                 max_iterations=None):
        self.llm = llm
        self.registry = registry
        self.ctx = ctx
        self.observer = observer or RunObserver()
        self.conversation = conversation
        if max_iterations is None:
            try:
                max_iterations = int(ctx.shell.get_config(
                    "orchestrator_max_iterations", DEFAULT_MAX_ITERATIONS))
            except Exception:
                max_iterations = DEFAULT_MAX_ITERATIONS
        self.max_iterations = max_iterations

    def run_agentic(self, user_prompt, sink, preset_extra="", preset_id="free"):
        started = time.monotonic()
        # En mode configuré "auto", le prompt système garde le protocole JSON
        # (un flip natif→json en cours de run reste couvert).
        prompt_mode = (self.llm.configured_mode
                       if self.llm.configured_mode == "auto"
                       else self.llm.effective_mode())
        system_prompt = prompts.build_system(
            self.ctx.app, self.registry, prompt_mode, preset_extra)

        messages = [{"role": "system", "content": system_prompt}]
        if self.conversation is not None:
            messages.extend(self.conversation.context_messages())
        messages.append({"role": "user", "content": user_prompt})
        tools = self.registry.openai_tools(self.ctx.app)

        self.observer.on_run_start(self.llm.effective_mode())
        result = RunResult(ok=False, reason="max_iterations")
        try:
            for iteration in range(self.max_iterations):
                step = self.llm.step(messages, tools=tools,
                                     on_text_delta=sink.stream_delta)
                if step.error:
                    message = error_message(step.error)
                    self.observer.on_error(step.error, message)
                    result = RunResult(ok=False, iterations=iteration + 1,
                                       reason=step.error, text=message)
                    return result
                if step.tool_calls:
                    self.observer.on_tool_calls(step.tool_calls)
                    results = []
                    for call in step.tool_calls:
                        call_started = time.monotonic()
                        tool_result = self.registry.call_tool(
                            call.name, call.arguments, self.ctx, call_id=call.id)
                        duration_ms = int((time.monotonic() - call_started) * 1000)
                        self.observer.on_tool_result(call, tool_result, duration_ms)
                        results.append(tool_result)
                    messages.extend(self.llm.encode_tool_exchange(step, results))
                    continue

                final_text = step.text.strip()
                sink.finish(final_text, step.streamed)
                self.observer.on_final(final_text)
                if self.conversation is not None:
                    self.conversation.append("user", user_prompt, self.ctx.app)
                    self.conversation.append("assistant", final_text, self.ctx.app)
                result = RunResult(ok=True, iterations=iteration + 1,
                                   text=final_text)
                return result

            self.observer.on_error("max_iterations",
                                   "L'assistant n'a pas convergé — réessayez en "
                                   "précisant la demande.")
            return result
        finally:
            self.ctx.undo_end()
            self.ctx.shell.telemetry("AssistantRun", {
                "plugin.action": "assistant.run",
                "assistant.preset": preset_id,
                "assistant.mode": self.llm.effective_mode(),
                "assistant.iterations": str(result.iterations),
                "assistant.ok": str(result.ok).lower(),
                "assistant.duration_ms": str(int((time.monotonic() - started) * 1000)),
            })
