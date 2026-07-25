"""Pont coquille → moteur : l'unique fonction appelée par le dispatcher.

Import paresseux depuis le dispatcher de la coquille — zéro coût au chargement
de l'extension tant que la palette n'est pas ouverte.
"""

from .shell_facade import MainJobShell


def _apply_settings_result(job, result):
    """Reprise de menu_actions.shared.apply_settings_result (duck-typée)."""
    if not isinstance(result, dict):
        return
    if "endpoint" in result and str(result["endpoint"]).startswith("http"):
        job.set_config("llm_base_urls", result["endpoint"])
    if "api_key" in result:
        job.set_config("llm_api_tokens", result["api_key"])
    if "model" in result:
        job.set_config("llm_default_models", result["model"])


def _open_documentation(job):
    import webbrowser
    doc_url = job.get_config("doc_url", "")
    if doc_url:
        webbrowser.open(doc_url)
        return
    portal_url = job.get_config("portal_url", "")
    if portal_url:
        webbrowser.open(portal_url)


def open_palette(job, model):
    """Ouvre la palette universelle sur le document courant."""
    shell = MainJobShell(job)
    if hasattr(model, "Text"):
        app = "writer"
    elif hasattr(model, "Sheets"):
        app = "calc"
    else:
        try:
            job._show_message("MIrAI — Assistant",
                              "Ouvrez un document Writer ou Calc pour "
                              "utiliser l'assistant.")
        except Exception:
            pass
        return None

    shell.telemetry("AssistantOpen", {"plugin.action": "assistant.open",
                                      "assistant.app": app})

    callbacks = {
        "settings": lambda: _apply_settings_result(job, job.settings_box("Settings")),
        "about": lambda: job._show_about_dialog(),
        "documentation": lambda: _open_documentation(job),
    }

    from ..ui.palette import open_or_focus
    return open_or_focus(job.ctx, shell, app, callbacks)
