"""Writer menu actions extracted from MainJob.trigger."""

from .shared import apply_settings_result


def _extend_selection(job, text, selection, text_range):
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
        system_prompt = job.get_config("extend_selection_system_prompt", "")
        prompt = text_range.getString()
        max_tokens = job.get_config("extend_selection_max_tokens", 15000)

        api_type = str(job.get_config("api_type", "completions")).lower()
        request = job.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)

        cursor = text.createTextCursorByRange(text_range)
        cursor.collapseToEnd()

        text.insertString(cursor, "\n\n---début-du-texte-généré---\n", False)

        def append_text(chunk_text):
            text.insertString(cursor, chunk_text, False)

        job.stream_request(request, api_type, append_text)
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


def _summarize_selection(job, text, selection, text_range):
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
            """TEXT TO SUMMARIZE:
"""
            + original_text
            + """

Create the shortest possible summary that captures the essential information.
Be extremely concise - use the minimum words necessary.
Do NOT ask any questions.
Output ONLY the summary text without any introduction or explanation.

SUMMARY:
"""
        )

        system_prompt = (
            "You are a professional summarizer. Create ultra-concise summaries "
            "using the minimum words necessary while preserving key information."
        )
        max_tokens = max(100, len(original_text) // 4)

        api_type = str(job.get_config("api_type", "completions")).lower()
        request = job.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)

        cursor = text.createTextCursorByRange(text_range)
        cursor.collapseToEnd()

        text.insertString(cursor, "\n\n---début-du-résumé---\n", False)

        summary_text = ""
        stop_phrases = [
            "end of document",
            "end of the document",
            "[END]",
            "---END---",
        ]

        def append_summary(chunk_text):
            nonlocal summary_text
            summary_text += chunk_text

            for stop_phrase in stop_phrases:
                if stop_phrase.lower() in summary_text.lower():
                    pos = summary_text.lower().find(stop_phrase.lower())
                    summary_text = summary_text[:pos].rstrip()
                    return

            text.insertString(cursor, chunk_text, False)

        job.stream_request(request, api_type, append_summary)
        text.insertString(cursor, "\n---fin-du-résumé---\n", False)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _simplify_selection(job, text, selection, text_range):
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
            """TEXT TO REFORMULATE:
"""
            + original_text
            + """

IMPORTANT: Rewrite this text in the SAME LANGUAGE as the original text.
Rewrite in clear, simple language that everyone can understand.
Use:
- Short sentences
- Common words (avoid jargon and technical terms)
- Active voice
- Concrete examples when possible

CRITICAL:
- Keep the SAME LANGUAGE as the original text
- Do NOT translate to another language
- Do NOT ask questions
- Do NOT add explanations
- Output ONLY the reformulated text

REFORMULATED VERSION:
"""
        )

        system_prompt = (
            "You are a plain language expert. Rewrite complex text in clear, "
            "simple language accessible to all readers. ALWAYS use the same "
            "language as the input text. Use short sentences and common words."
        )
        max_tokens = len(original_text) + job.get_config("edit_selection_max_new_tokens", 15000)

        api_type = str(job.get_config("api_type", "completions")).lower()
        request = job.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)

        cursor = text.createTextCursorByRange(text_range)
        cursor.collapseToEnd()

        text.insertString(cursor, "\n\n---reformulation-du-texte---\n", False)

        simplified_text = ""
        stop_phrases = [
            "end of document",
            "end of the document",
            "[END]",
            "---END---",
        ]
        question_patterns = [
            "would you like",
            "do you want",
            "should i",
            "can i help",
            "voulez-vous",
            "souhaitez-vous",
            "dois-je",
            "puis-je",
            "here is",
            "voici",
            "voilà",
        ]

        def append_simplified(chunk_text):
            nonlocal simplified_text
            simplified_text += chunk_text

            lower_text = simplified_text.lower()
            for pattern in question_patterns:
                if pattern in lower_text:
                    cursor.gotoStart(False)
                    cursor.gotoEnd(True)
                    text.insertString(cursor, "[Le modèle a posé une question. Veuillez réessayer.]", False)
                    simplified_text = ""
                    return

            for stop_phrase in stop_phrases:
                if stop_phrase.lower() in simplified_text.lower():
                    pos = simplified_text.lower().find(stop_phrase.lower())
                    simplified_text = simplified_text[:pos].rstrip()
                    return

            text.insertString(cursor, chunk_text, False)

        job.stream_request(request, api_type, append_simplified)
        text.insertString(cursor, "\n---fin-de-reformulation---\n", False)
    except Exception as e:
        text_range = selection.getByIndex(0)
        text_range.setString(text_range.getString() + ": " + str(e))


def _open_mirai_website(job):
    job._send_telemetry("OpenmiraiWebsite", {"action": "open_website"})
    try:
        import webbrowser

        webbrowser.open("https://mirai.interieur.gouv.fr")
    except Exception as e:
        job._log(f"Error opening website: {str(e)}")


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
    selection = model.CurrentController.getSelection()
    text_range = selection.getByIndex(0)

    if args == "ExtendSelection":
        _extend_selection(job, text, selection, text_range)
    elif args == "EditSelection":
        _edit_selection(job, text, selection, text_range)
    elif args == "SummarizeSelection":
        _summarize_selection(job, text, selection, text_range)
    elif args == "SimplifySelection":
        _simplify_selection(job, text, selection, text_range)
    elif args == "OpenmiraiWebsite":
        _open_mirai_website(job)
    elif args == "MenuSeparator":
        return True
    elif args == "settings":
        _open_settings(job, selection)

    return True

