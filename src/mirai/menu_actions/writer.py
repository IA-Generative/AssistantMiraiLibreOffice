"""Writer menu actions extracted from MainJob.trigger."""

import re

from .shared import apply_settings_result

_RE_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _strip_think_blocks(text):
    """Remove <think>...</think> chain-of-thought blocks (e.g. deepseek-r1)."""
    return _RE_THINK.sub("", text).lstrip("\n")


def _check_stop_phrase(accumulated, chunk, stop_phrases):
    """Return (text_to_insert, stop_detected) for the current streaming chunk.

    When a stop phrase is found in *accumulated*, return the portion of *chunk*
    that precedes the stop phrase (may be empty) and True.
    Otherwise return *chunk* unchanged and False.
    """
    acc_lower = accumulated.lower()
    for phrase in stop_phrases:
        pos = acc_lower.find(phrase.lower())
        if pos == -1:
            continue
        already_inserted = len(accumulated) - len(chunk)
        partial = chunk[:max(0, pos - already_inserted)] if pos > already_inserted else ""
        return partial, True
    return chunk, False


def _scroll_to_cursor(controller, cursor):
    """Move the view cursor to the text cursor so the document auto-scrolls."""
    try:
        view_cursor = controller.getViewCursor()
        view_cursor.gotoRange(cursor.getEnd(), False)
    except Exception:
        pass


def _undo_context(model, label):
    """Context manager that groups all Writer insertions into one undo step."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        mgr = None
        try:
            mgr = model.getUndoManager()
            mgr.enterUndoContext(label)
        except Exception:
            mgr = None
        try:
            yield
        finally:
            if mgr is not None:
                try:
                    mgr.leaveUndoContext()
                except Exception:
                    pass

    return _ctx()


_EXTEND_QUESTION_PATTERNS = [
    "puis-je vous", "puis-je t'", "comment puis-je", "en quoi puis-je",
    "que puis-je faire", "puis-je vous aider",
    "pouvez-vous préciser", "pouvez-vous clarifier",
    "could you clarify", "how can i help", "would you like me to",
    "voulez-vous que je", "souhaitez-vous que",
]


def _make_extend_callback(text_obj, cursor, controller, done_flag, on_question):
    """Return a streaming callback for extend_selection.

    Inserts each chunk unless a conversational question pattern is detected,
    in which case *on_question()* is called and further chunks are ignored.
    """
    accumulated = [""]

    def _callback(chunk_text):
        if done_flag[0]:
            return
        accumulated[0] += chunk_text
        lower = accumulated[0].lower()
        for pattern in _EXTEND_QUESTION_PATTERNS:
            if pattern in lower:
                done_flag[0] = True
                on_question()
                return
        text_obj.insertString(cursor, chunk_text, False)
        _scroll_to_cursor(controller, cursor)

    return _callback


def _extend_selection(job, text, selection, text_range, controller=None, model=None):
    job._send_telemetry(
        "ExtendSelection",
        {
            "action": "extend_selection",
            "text_length": str(len(text_range.getString())),
        },
    )

    if len(text_range.getString()) <= 0:
        return

    try:
        base_text = text_range.getString()

        # Directive system prompt — prevents conversational responses up-front.
        configured_sp = str(job.get_config("extend_selection_system_prompt", "") or "").strip()
        directive = (
            "Continue DIRECTEMENT le texte fourni par l'utilisateur. "
            "Écris uniquement la suite naturelle, sans question, sans reformulation, "
            "sans introduction."
        )
        system_prompt = (directive + " " + configured_sp) if configured_sp else directive

        max_tokens = job.get_config("extend_selection_max_tokens", 15000)
        api_type = str(job.get_config("api_type", "completions")).lower()
        request = job.make_api_request(base_text, system_prompt, max_tokens, api_type=api_type)

        cursor = text.createTextCursorByRange(text_range)
        cursor.collapseToEnd()

        extend_done = [False]
        retry_needed = [False]

        def _on_question_attempt1():
            retry_needed[0] = True

        with _undo_context(model, "Générer la suite"):
            text.insertString(cursor, "\n\n---début-du-texte-généré---\n", False)

            job.stream_request(
                request, api_type,
                _make_extend_callback(text, cursor, controller, extend_done, _on_question_attempt1),
            )

            # Auto-retry with a stronger directive when the model asked a question.
            if retry_needed[0]:
                extend_done[0] = False
                retry_sp = (
                    "Tu dois CONTINUER le texte de l'utilisateur mot après mot, "
                    "comme si tu en étais l'auteur. Il est INTERDIT de poser une question "
                    "ou de reformuler. Commence immédiatement par les mots qui suivent "
                    "naturellement le texte fourni."
                )
                retry_prompt = (
                    "Voici le texte à continuer :\n\n" + base_text
                    + "\n\nÉcris UNIQUEMENT la suite directe, sans aucune introduction."
                )
                retry_request = job.make_api_request(
                    retry_prompt, retry_sp, max_tokens, api_type=api_type
                )

                def _on_question_retry():
                    text.insertString(
                        cursor,
                        "\n[Le modèle n'a pas pu continuer le texte."
                        " Essayez de sélectionner plus de contexte.]",
                        False,
                    )

                job.stream_request(
                    retry_request, api_type,
                    _make_extend_callback(text, cursor, controller, extend_done, _on_question_retry),
                )

            text.insertString(cursor, "\n---fin-du-texte-généré---\n", False)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _edit_selection(job, text, selection, text_range):
    job._send_telemetry(
        "EditSelection",
        {
            "action": "edit_selection",
            "text_length": str(len(text_range.getString())),
        },
    )

    try:
        job._show_edit_selection_dialog(text, text_range)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _resize_selection(job, text, selection, text_range, controller=None, model=None):
    job._send_telemetry(
        "ResizeSelection",
        {
            "action": "resize_selection",
            "text_length": str(len(text_range.getString())),
        },
    )

    try:
        job._show_resize_dialog(text, text_range, controller=controller, model=model)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _summarize_selection(job, text, selection, text_range, controller=None, model=None):
    job._send_telemetry(
        "SummarizeSelection",
        {
            "action": "summarize_selection",
            "text_length": str(len(text_range.getString())),
        },
    )

    try:
        original_text = text_range.getString()
        if len(original_text.strip()) == 0:
            return

        prompt = (
            """TEXTE À RÉSUMER :
"""
            + original_text
            + """

Crée le résumé le plus court possible qui capture les informations essentielles.
Sois extrêmement concis — utilise le minimum de mots nécessaire.
Ne pose AUCUNE question.
Produis UNIQUEMENT le texte du résumé, sans introduction ni explication.
IMPORTANT : Réponds dans la MÊME LANGUE que le texte original.

RÉSUMÉ :
"""
        )

        system_prompt = (
            "Tu es un résumeur professionnel. Tu crées des résumés ultra-concis "
            "en utilisant le minimum de mots nécessaire tout en préservant "
            "les informations clés. Tu réponds TOUJOURS dans la même langue "
            "que le texte fourni."
        )
        max_tokens = int(job.get_config("summarize_selection_max_tokens", 15000))

        api_type = str(job.get_config("api_type", "completions")).lower()
        request = job.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)

        cursor = text.createTextCursorByRange(text_range)
        cursor.collapseToEnd()

        summary_text = ""
        summary_done = [False]
        stop_phrases = [
            "[END]",
            "---END---",
        ]

        with _undo_context(model, "Résumer"):
            text.insertString(cursor, "\n\n---début-du-résumé---\n", False)

            def append_summary(chunk_text):
                nonlocal summary_text
                if summary_done[0]:
                    return
                summary_text += chunk_text
                to_insert, done = _check_stop_phrase(summary_text, chunk_text, stop_phrases)
                if done:
                    summary_text = summary_text[:len(summary_text) - len(chunk_text) + len(to_insert)].rstrip()
                    summary_done[0] = True
                if to_insert:
                    text.insertString(cursor, to_insert, False)
                    _scroll_to_cursor(controller, cursor)

            job.stream_request(request, api_type, append_summary)
            text.insertString(cursor, "\n---fin-du-résumé---\n", False)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _simplify_selection(job, text, selection, text_range, controller=None, model=None):
    job._send_telemetry(
        "SimplifySelection",
        {
            "action": "simplify_selection",
            "text_length": str(len(text_range.getString())),
        },
    )

    try:
        original_text = text_range.getString()
        if len(original_text.strip()) == 0:
            return

        prompt = (
            """TEXTE À REFORMULER :
"""
            + original_text
            + """

Réécris ce texte dans un langage clair et simple compréhensible par tous.
Utilise :
- Des phrases courtes
- Des mots courants (évite le jargon et les termes techniques)
- La voix active
- Des exemples concrets quand c'est possible

RÈGLES :
- Garde la MÊME LANGUE que le texte original
- Ne traduis PAS dans une autre langue
- Ne pose AUCUNE question
- N'ajoute AUCUNE explication
- Produis UNIQUEMENT le texte reformulé

VERSION REFORMULÉE :
"""
        )

        system_prompt = (
            "Tu es un expert en langage simplifié. Tu réécris les textes complexes "
            "dans un langage clair et simple accessible à tous. Tu utilises TOUJOURS "
            "la même langue que le texte fourni. Tu utilises des phrases courtes "
            "et des mots courants."
        )
        configured_sp = str(job.get_config("simplify_selection_system_prompt", "") or "").strip()
        if configured_sp:
            system_prompt = configured_sp + " " + system_prompt
        max_tokens = len(original_text) + job.get_config("simplify_selection_max_tokens", 15000)

        api_type = str(job.get_config("api_type", "completions")).lower()
        request = job.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)

        cursor = text.createTextCursorByRange(text_range)
        cursor.collapseToEnd()

        simplified_text = ""
        simplify_done = [False]
        stop_phrases = [
            "[END]",
            "---END---",
        ]
        # Only true conversational questions — NOT response format prefixes like
        # "Voici le texte reformulé" which are normal model output patterns.
        question_patterns = [
            "would you like", "do you want", "should i", "can i help",
            "voulez-vous", "souhaitez-vous", "dois-je", "puis-je",
        ]

        with _undo_context(model, "Reformuler"):
            text.insertString(cursor, "\n\n---reformulation-du-texte---\n", False)

            def append_simplified(chunk_text):
                nonlocal simplified_text
                if simplify_done[0]:
                    return
                simplified_text += chunk_text
                lower_text = simplified_text.lower()
                for pattern in question_patterns:
                    if pattern in lower_text:
                        cursor.gotoStart(False)
                        cursor.gotoEnd(True)
                        text.insertString(cursor, "[Le modèle a posé une question. Veuillez réessayer.]", False)
                        simplify_done[0] = True
                        return
                to_insert, done = _check_stop_phrase(simplified_text, chunk_text, stop_phrases)
                if done:
                    simplified_text = simplified_text[:len(simplified_text) - len(chunk_text) + len(to_insert)].rstrip()
                    simplify_done[0] = True
                if to_insert:
                    text.insertString(cursor, to_insert, False)
                    _scroll_to_cursor(controller, cursor)

            job.stream_request(request, api_type, append_simplified)
            text.insertString(cursor, "\n---fin-de-reformulation---\n", False)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _open_mirai_website(job):
    job._send_telemetry("OpenmiraiWebsite", {"action": "open_website"})
    try:
        import webbrowser

        portal_url = job.get_config("portal_url", "")
        if portal_url:
            webbrowser.open(portal_url)
        else:
            webbrowser.open("https://mirai.interieur.gouv.fr")
    except Exception as e:
        job._log(f"Error opening website: {str(e)}")


def _open_documentation(job):
    job._send_telemetry("OpenDocumentation", {"action": "open_documentation"})
    try:
        import webbrowser

        doc_url = job.get_config("doc_url", "")
        if doc_url:
            webbrowser.open(doc_url)
            return
        portal_url = job.get_config("portal_url", "")
        if portal_url:
            webbrowser.open(portal_url)
    except Exception as e:
        job._log(f"Error opening documentation: {str(e)}")


def _open_settings(job, selection):
    job._send_telemetry("OpenSettings", {"action": "open_settings"})
    try:
        result = job.settings_box("Settings")
        apply_settings_result(job, result)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ":error: " + str(e))


def handle_writer_action(job, args, model):
    if not hasattr(model, "Text"):
        return False

    job._log("Processing Writer document")
    text = model.Text
    ctrl = model.CurrentController
    selection = ctrl.getSelection()
    text_range = selection.getByIndex(0)

    if args == "ExtendSelection":
        _extend_selection(job, text, selection, text_range, controller=ctrl, model=model)
    elif args == "EditSelection":
        _edit_selection(job, text, selection, text_range)
    elif args == "SummarizeSelection":
        _summarize_selection(job, text, selection, text_range, controller=ctrl, model=model)
    elif args == "SimplifySelection":
        _simplify_selection(job, text, selection, text_range, controller=ctrl, model=model)
    elif args == "ResizeSelection":
        _resize_selection(job, text, selection, text_range, controller=ctrl, model=model)
    elif args == "AboutDialog":
        try:
            job._show_about_dialog()
        except Exception as e:
            job._log(f"AboutDialog error: {e}")
    elif args == "OpenmiraiWebsite":
        _open_mirai_website(job)
    elif args == "Documentation":
        _open_documentation(job)
    elif args == "MenuSeparator":
        return True
    elif args == "settings":
        _open_settings(job, selection)

    return True

