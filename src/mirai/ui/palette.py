"""Palette universelle MIrAI — fenêtre de prompt non modale, style DSFR.

Point d'entrée unique de l'assistant : prompt libre + chips des fonctions
fréquentes + fil de conversation persisté + journal d'actions optionnel
(séquence des outils proposés puis exécutés, façon agent).

Threading : tout tourne sur le thread principal UNO. Pendant un run, le pump
SSE traite les événements UI (processEventsToIdle) — le drapeau `busy`
empêche toute réentrance depuis les listeners.
"""

import unohelper
from com.sun.star.awt import XKeyListener

from ..core.context import ToolContext
from ..core.conversation import ConversationStore
from ..core.llm_client import LLMClient
from ..core.orchestrator import Orchestrator, RunObserver
from ..core.registry import ToolRegistry
from ..core.sinks import PaletteSink, WriterReplaceSink
from ..core import presets as presets_module
from ..core.tools import register_all
from . import dsfr

try:
    from com.sun.star.awt.Key import RETURN as KEY_RETURN, ESCAPE as KEY_ESCAPE
except Exception:
    KEY_RETURN, KEY_ESCAPE = 1280, 1281

WIDTH = 580
MARGIN = 16
CHIP_HEIGHT = 28
CHIP_GAP = 8

TOOL_LABELS = {
    "writer_get_selection": "Lecture de la sélection",
    "writer_get_document_map": "Lecture du document",
    "writer_replace_selection": "Remplacement de la sélection",
    "writer_insert_text": "Insertion de texte",
    "writer_find_replace": "Remplacements dans le document",
    "calc_get_selection": "Lecture de la sélection",
    "calc_read_range": "Lecture d'une plage",
    "calc_get_sheet_overview": "Analyse de la structure",
    "calc_write_cells": "Écriture de cellules",
    "calc_write_result_column": "Écriture de la colonne résultat",
    "calc_set_formula": "Écriture de la formule",
    "calc_fill_formula_down": "Recopie de la formule",
}

_open_palette = [None]   # singleton de session


class _KeyHandler(unohelper.Base, XKeyListener):
    def __init__(self, on_return, on_escape):
        self._on_return = on_return
        self._on_escape = on_escape

    def keyPressed(self, event):
        try:
            if event.KeyCode == KEY_RETURN and not (event.Modifiers & 1):
                self._on_return()
            elif event.KeyCode == KEY_ESCAPE:
                self._on_escape()
        except Exception:
            pass

    def keyReleased(self, event):
        pass

    def disposing(self, event):
        pass


class _JournalObserver(RunObserver):
    """Alimente le journal d'actions de la palette (optionnel, repliable)."""

    def __init__(self, palette):
        self._palette = palette
        self.lines = []

    def _tool_label(self, call):
        return TOOL_LABELS.get(call.name, call.name)

    def _render(self):
        self._palette.set_journal_text("\n".join(self.lines))

    def on_run_start(self, mode):
        self.lines = [f"Mode outils : {mode}"]
        self._render()

    def on_tool_calls(self, calls):
        for call in calls:
            self.lines.append(f"⏳ {self._tool_label(call)}…")
        self._render()

    def on_tool_result(self, call, result, duration_ms):
        icon = "✓" if result.ok else "✗"
        label = self._tool_label(call)
        for index in range(len(self.lines) - 1, -1, -1):
            if self.lines[index] == f"⏳ {label}…":
                self.lines[index] = f"{icon} {label} ({duration_ms} ms)"
                break
        else:
            self.lines.append(f"{icon} {label} ({duration_ms} ms)")
        if not result.ok and result.error:
            self.lines.append(f"   ↳ {result.error[:120]}")
        self._render()

    def on_error(self, code, message):
        self.lines.append(f"⚠ {message}")
        self._render()


class AssistantPalette:
    def __init__(self, uno_ctx, shell, app, callbacks):
        self.uno_ctx = uno_ctx
        self.shell = shell
        self.app = app                      # "writer" | "calc" à l'ouverture
        self.callbacks = callbacks          # settings / about / documentation
        self.busy = False
        self.journal_visible = False
        self.registry = register_all(ToolRegistry())
        self.conversation = ConversationStore(shell.user_config_dir())
        self.dialog = None
        self._controls = {}
        self._models = {}
        self._handlers = []                 # garde les listeners vivants (GC)
        self._journal_height = 100
        self._build()

    # ── Construction ────────────────────────────────────────────────────
    def _build(self):
        toolkit = self.shell.toolkit()
        font = dsfr.probe_font(toolkit)
        self._font = font

        app_label = "Writer" if self.app == "writer" else "Calc"
        dialog, model = dsfr.make_dialog(
            self.uno_ctx, "MIrAI — Assistant", WIDTH, 100)  # hauteur recalculée
        self.dialog, self.model = dialog, model

        y = 0
        # Bandeau bleu France
        dsfr.add_control(dialog, model, "header", "FixedText", 0, 0, WIDTH, 44, {
            "Label": f"   MIrAI — Assistant ({app_label})",
            "BackgroundColor": dsfr.TOKENS["primary"],
            "TextColor": dsfr.TOKENS["text_inverted"],
            "FontName": font, "FontHeight": 12, "FontWeight": 150.0,
            "VerticalAlign": 1,
        })
        y = 52

        # Chips des presets
        y = self._build_chips(y, font)

        # Zone de prompt
        prompt_control, prompt_model = dsfr.add_control(
            dialog, model, "prompt", "Edit", MARGIN, y, WIDTH - 2 * MARGIN, 56, {
                "MultiLine": True, "AutoVScroll": True,
                "FontName": font, "FontHeight": 10,
                "TextColor": dsfr.TOKENS["text_body"],
                "Border": 2, "BorderColor": dsfr.TOKENS["border"],
                "HelpText": "Décrivez ce que l'assistant doit faire",
            })
        self._controls["prompt"] = prompt_control
        self._models["prompt"] = prompt_model
        y += 56 + 8

        # Statut + bouton Envoyer
        _, status_model = dsfr.add_control(
            dialog, model, "status", "FixedText", MARGIN, y + 6,
            WIDTH - 2 * MARGIN - 130, 20, {
                "Label": "",
                "TextColor": dsfr.TOKENS["text_mention"],
                "FontName": font, "FontHeight": 9,
            })
        self._models["status"] = status_model
        send_control, send_model = dsfr.add_primary_button(
            dialog, model, "send", "Envoyer  ⏎", WIDTH - MARGIN - 120, y,
            120, 32, font, self._on_send)
        self._models["send"] = send_model
        y += 32 + 10

        # Fil de conversation (réponses)
        _, response_model = dsfr.add_control(
            dialog, model, "response", "Edit", MARGIN, y,
            WIDTH - 2 * MARGIN, 200, {
                "MultiLine": True, "ReadOnly": True, "VScroll": True,
                "FontName": font, "FontHeight": 10,
                "TextColor": dsfr.TOKENS["text_body"],
                "BackgroundColor": dsfr.TOKENS["bg_alt"],
                "Border": 2, "BorderColor": dsfr.TOKENS["border"],
            })
        self._models["response"] = response_model
        y += 200 + 6

        # Journal d'actions (repliable)
        toggle_control, toggle_model = dsfr.add_control(
            dialog, model, "journal_toggle", "FixedText", MARGIN, y,
            220, 16, {
                "Label": "▸ Voir les actions",
                "TextColor": dsfr.TOKENS["primary"],
                "FontName": font, "FontHeight": 9,
            })
        self._models["journal_toggle"] = toggle_model
        toggle_handler = dsfr.ClickHandler(
            toggle_model, on_click=self._toggle_journal,
            fg=dsfr.TOKENS["primary"], fg_hover=dsfr.TOKENS["primary_hover"])
        toggle_control.addMouseListener(toggle_handler)
        self._handlers.append(toggle_handler)
        y += 16 + 4
        self._journal_y = y

        journal_control, journal_model = dsfr.add_control(
            dialog, model, "journal", "Edit", MARGIN, y,
            WIDTH - 2 * MARGIN, self._journal_height, {
                "MultiLine": True, "ReadOnly": True, "VScroll": True,
                "FontName": font, "FontHeight": 9,
                "TextColor": dsfr.TOKENS["text_mention"],
                "BackgroundColor": dsfr.TOKENS["bg_accent"],
                "Border": 2, "BorderColor": dsfr.TOKENS["border"],
            })
        self._controls["journal"] = journal_control
        self._models["journal"] = journal_model
        journal_control.setVisible(False)

        self._footer_base_y = y
        self._build_footer(font)
        self._apply_layout()

        # Peer + centrage sur la fenêtre du document
        frame = self.uno_ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.uno_ctx).getCurrentFrame()
        parent_window = frame.getContainerWindow() if frame else None
        dialog.createPeer(toolkit, parent_window)
        if parent_window is not None:
            try:
                ps = parent_window.getPosSize()
                dialog.setPosSize(ps.X + max(0, (ps.Width - WIDTH) // 2),
                                  ps.Y + max(0, (ps.Height - self._height) // 3),
                                  0, 0, 3)  # POS
            except Exception:
                pass

        key_handler = _KeyHandler(self._on_send, self.close)
        prompt_control.addKeyListener(key_handler)
        self._handlers.append(key_handler)

        # Restaure le fil persisté
        self._render_conversation()

    def _build_chips(self, y, font):
        x = MARGIN
        for index, preset in enumerate(presets_module.presets_for(self.app)):
            width = 24 + 8 * len(preset.label)
            if x + width > WIDTH - MARGIN:
                x = MARGIN
                y += CHIP_HEIGHT + CHIP_GAP
            control, chip_model = dsfr.add_chip(
                self.dialog, self.model, f"chip_{preset.id}", preset.label,
                x, y, width, font,
                on_click=(lambda p=preset: self._on_chip(p)))
            handler_ref = control  # les listeners sont retenus par add_chip
            self._handlers.append(handler_ref)
            x += width + CHIP_GAP
        return y + CHIP_HEIGHT + 10

    def _build_footer(self, font):
        # Positions Y appliquées dans _apply_layout()
        specs = [
            ("link_settings", "Réglages", 90, self.callbacks.get("settings")),
            ("link_about", "À propos", 80, self.callbacks.get("about")),
            ("link_doc", "Documentation", 110, self.callbacks.get("documentation")),
            ("link_clear", "🗑 Nouvelle conversation", 170, self._on_clear),
        ]
        x = MARGIN
        for name, label, width, callback in specs:
            control, link_model = dsfr.add_link(
                self.dialog, self.model, name, label, x, 0, width, font,
                callback or (lambda: None))
            self._controls[name] = control
            x += width + 12
        _, hint_model = dsfr.add_control(
            self.dialog, self.model, "hint", "FixedText",
            x, 0, WIDTH - MARGIN - x, 16, {
                "Label": "Échap : fermer",
                "TextColor": dsfr.TOKENS["text_mention"],
                "FontName": font, "FontHeight": 8, "Align": 2,
            })
        self._controls["hint"] = hint_model  # modèle suffisant (position via contrôle)

    def _apply_layout(self):
        journal_h = (self._journal_height + 6) if self.journal_visible else 0
        footer_y = self._footer_base_y + journal_h
        for name in ("link_settings", "link_about", "link_doc", "link_clear"):
            control = self._controls.get(name)
            if control is not None:
                ps = control.getPosSize()
                control.setPosSize(ps.X, footer_y, 0, 0, 2)  # Y uniquement
        hint = self.dialog.getControl("hint")
        if hint is not None:
            ps = hint.getPosSize()
            hint.setPosSize(ps.X, footer_y, 0, 0, 2)
        self._height = footer_y + 16 + MARGIN
        ps = self.dialog.getPosSize()
        self.dialog.setPosSize(ps.X, ps.Y, WIDTH, self._height, 15)

    # ── Affichage ───────────────────────────────────────────────────────
    def show(self):
        self.dialog.setVisible(True)
        try:
            self._controls["prompt"].setFocus()
        except Exception:
            pass

    def close(self):
        try:
            self.dialog.setVisible(False)
            self.dialog.dispose()
        except Exception:
            pass
        if _open_palette[0] is self:
            _open_palette[0] = None

    def set_status(self, message):
        self._models["status"].Label = message

    def set_journal_text(self, text):
        self._models["journal"].Text = text

    def _toggle_journal(self):
        self.journal_visible = not self.journal_visible
        self._models["journal_toggle"].Label = (
            "▾ Masquer les actions" if self.journal_visible
            else "▸ Voir les actions")
        self._controls["journal"].setVisible(self.journal_visible)
        self._apply_layout()

    def _render_conversation(self):
        entries = self.conversation.load()
        lines = []
        for entry in entries:
            prefix = "Vous : " if entry["role"] == "user" else "MIrAI : "
            lines.append(prefix + entry["text"])
        self._models["response"].Text = "\n\n".join(lines)

    def _append_response(self, prefix, text=""):
        current = self._models["response"].Text
        addition = (prefix + text) if text or prefix else ""
        self._models["response"].Text = (
            (current + "\n\n" + addition) if current else addition)

    def _stream_response(self, chunk):
        self._models["response"].Text = self._models["response"].Text + chunk

    def _on_clear(self):
        if self.busy:
            return
        self.conversation.clear()
        self._models["response"].Text = ""
        self.set_journal_text("")
        self.set_status("Conversation effacée.")

    # ── Exécution ───────────────────────────────────────────────────────
    def _current_context(self):
        desktop = self.uno_ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.uno_ctx)
        model = desktop.getCurrentComponent()
        if model is None:
            return None
        if hasattr(model, "Text"):
            app = "writer"
        elif hasattr(model, "Sheets"):
            app = "calc"
        else:
            return None
        return ToolContext(self.uno_ctx, model, model.CurrentController,
                           app, self.shell)

    def _prompt_text(self):
        try:
            return str(self._models["prompt"].Text or "")
        except Exception:
            return ""

    def _on_chip(self, preset):
        self._run(preset=preset)

    def _on_send(self):
        self._run(preset=None)

    def _run(self, preset=None):
        if self.busy:
            return
        prompt_text = self._prompt_text().strip()
        if preset is None and not prompt_text:
            self.set_status("Tapez d'abord votre demande.")
            return
        if preset is not None and preset.needs_input and not prompt_text:
            self.set_status(preset.input_hint or "Précisez votre demande.")
            return

        ctx = self._current_context()
        if ctx is None:
            self.set_status("Ouvrez un document Writer ou Calc.")
            return
        if preset is not None and ctx.app not in preset.apps:
            wanted = "Writer" if "writer" in preset.apps else "Calc"
            self.set_status(f"Cette action nécessite un document {wanted}.")
            return

        self.busy = True
        self._models["send"].Label = "…"
        self.set_status("L'assistant travaille…")
        observer = _JournalObserver(self)
        shown = prompt_text if preset is None else (
            preset.label + ((" — " + prompt_text) if prompt_text else ""))
        self._append_response("Vous : ", shown)
        try:
            if preset is not None and preset.mode == "pipeline":
                message = preset.runner(ctx, self.shell, prompt_text, None)
                self._append_response("MIrAI : ", message)
                self.conversation.append("user", shown, ctx.app)
                self.conversation.append("assistant", message, ctx.app)
            else:
                llm = LLMClient(self.shell)
                orchestrator = Orchestrator(
                    llm, self.registry, ctx, observer=observer,
                    conversation=self.conversation)
                extra = ""
                user_prompt = prompt_text
                sink = PaletteSink(on_delta=None)
                if preset is not None:
                    if preset.build_extra:
                        extra = preset.build_extra(ctx, self.shell, prompt_text)
                    if preset.prompt_template:
                        user_prompt = preset.prompt_template(prompt_text)
                    if preset.sink_spec == "auto_edit":
                        selection = ""
                        try:
                            selection = ctx.controller.getSelection() \
                                .getByIndex(0).getString()
                        except Exception:
                            pass
                        if selection.strip():
                            sink = WriterReplaceSink(ctx)
                self._append_response("MIrAI : ")
                if isinstance(sink, PaletteSink):
                    sink = PaletteSink(on_delta=self._stream_response)
                result = orchestrator.run_agentic(
                    user_prompt, sink,
                    preset_extra=extra,
                    preset_id=preset.id if preset else "free")
                if not result.ok:
                    self._stream_response("⚠ " + (result.text or result.reason))
                elif not isinstance(sink, PaletteSink):
                    self._stream_response(result.text or "Modification appliquée.")
            self._models["prompt"].Text = ""
            self.set_status("")
        except Exception as exc:
            self.shell.log(f"[palette] run error: {exc}")
            self.set_status("Erreur inattendue — voir le journal.")
            self._append_response("MIrAI : ", f"⚠ Erreur : {exc}")
        finally:
            self.busy = False
            self._models["send"].Label = "Envoyer  ⏎"


def open_or_focus(uno_ctx, shell, app, callbacks):
    """Ouvre la palette (ou la ramène au premier plan si déjà ouverte)."""
    existing = _open_palette[0]
    if existing is not None:
        try:
            existing.dialog.setVisible(True)
            existing.dialog.setFocus()
            return existing
        except Exception:
            _open_palette[0] = None
    palette = AssistantPalette(uno_ctx, shell, app, callbacks)
    _open_palette[0] = palette
    palette.show()
    return palette
