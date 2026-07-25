"""Palette universelle MIrAI — fenêtre de prompt non modale, style DSFR.

Point d'entrée unique de l'assistant : prompt libre + chips des fonctions
fréquentes + fil de conversation persisté + journal d'actions optionnel
(séquence des outils proposés puis exécutés, façon agent).

Layout MESURÉ : les positions/tailles ne sont jamais estimées en pixels fixes
— après création du peer, chaque contrôle texte est dimensionné via
getPreferredSize() (tailles réelles de rendu, HiDPI/Retina compris) et le
reste est dérivé d'un facteur d'échelle. Invariant : relancer _layout() est
toujours sûr (repli du journal, etc.).

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
        self._models = {}
        self._handlers = []                 # garde les listeners vivants (GC)
        self._chip_names = []
        self._build()

    # ── Construction (création des contrôles, positions posées par _layout) ──
    def _build(self):
        toolkit = self.shell.toolkit()
        font = dsfr.probe_font(toolkit)
        self._font = font

        app_label = "Writer" if self.app == "writer" else "Calc"
        dialog, model = dsfr.make_dialog(
            self.uno_ctx, "MIrAI — Assistant", 640, 560)
        self.dialog, self.model = dialog, model

        _, header_model = dsfr.add_control(
            dialog, model, "header", "FixedText", 0, 0, 640, 40, {
                "Label": f"  MIrAI — Assistant ({app_label})",
                "BackgroundColor": dsfr.TOKENS["primary"],
                "TextColor": dsfr.TOKENS["text_inverted"],
                "FontName": font, "FontHeight": 12, "FontWeight": 150.0,
                "VerticalAlign": 1,
            })
        self._models["header"] = header_model

        for preset in presets_module.presets_for(self.app):
            name = f"chip_{preset.id}"
            control, _chip_model = dsfr.add_chip(
                dialog, model, name, preset.label, 0, 0, 100, 28, font,
                on_click=(lambda p=preset: self._on_chip(p)))
            self._chip_names.append(name)
            self._handlers.append(control)

        prompt_control, prompt_model = dsfr.add_control(
            dialog, model, "prompt", "Edit", 0, 0, 100, 56, {
                "MultiLine": True, "AutoVScroll": True,
                "FontName": font, "FontHeight": 10,
                "TextColor": dsfr.TOKENS["text_body"],
                # Champ DSFR : fond contraste + bordure sombre, bien visible
                "BackgroundColor": dsfr.TOKENS["bg_contrast"],
                "Border": 2, "BorderColor": dsfr.TOKENS["text_body"],
                "HelpText": "Décrivez ce que l'assistant doit faire",
            })
        self._models["prompt"] = prompt_model

        _, status_model = dsfr.add_control(
            dialog, model, "status", "FixedText", 0, 0, 100, 18, {
                "Label": "",
                "TextColor": dsfr.TOKENS["text_mention"],
                "FontName": font, "FontHeight": 9,
            })
        self._models["status"] = status_model

        _, send_model = dsfr.add_primary_button(
            dialog, model, "send", "Envoyer  ⏎", 0, 0, 120, 32, font,
            self._on_send)
        self._models["send"] = send_model

        _, response_model = dsfr.add_control(
            dialog, model, "response", "Edit", 0, 0, 100, 200, {
                "MultiLine": True, "ReadOnly": True, "VScroll": True,
                "FontName": font, "FontHeight": 10,
                "TextColor": dsfr.TOKENS["text_body"],
                "BackgroundColor": dsfr.TOKENS["bg_alt"],
                "Border": 2, "BorderColor": dsfr.TOKENS["border"],
            })
        self._models["response"] = response_model

        toggle_control, toggle_model = dsfr.add_control(
            dialog, model, "journal_toggle", "FixedText", 0, 0, 160, 16, {
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

        journal_control, journal_model = dsfr.add_control(
            dialog, model, "journal", "Edit", 0, 0, 100, 100, {
                "MultiLine": True, "ReadOnly": True, "VScroll": True,
                "FontName": font, "FontHeight": 9,
                "TextColor": dsfr.TOKENS["text_mention"],
                "BackgroundColor": dsfr.TOKENS["bg_accent"],
                "Border": 2, "BorderColor": dsfr.TOKENS["border"],
            })
        self._models["journal"] = journal_model
        journal_control.setVisible(False)

        self._footer_specs = [
            ("link_settings", "Réglages", self.callbacks.get("settings")),
            ("link_about", "À propos", self.callbacks.get("about")),
            ("link_doc", "Documentation", self.callbacks.get("documentation")),
            ("link_clear", "🗑 Nouvelle conversation", self._on_clear),
        ]
        for name, label, callback in self._footer_specs:
            dsfr.add_link(dialog, model, name, label, 0, 0, 120, 16, font,
                          callback or (lambda: None))
        _, hint_model = dsfr.add_control(
            dialog, model, "hint", "FixedText", 0, 0, 120, 16, {
                "Label": "Échap : fermer",
                "TextColor": dsfr.TOKENS["text_mention"],
                "FontName": font, "FontHeight": 8, "Align": 2,
            })
        self._models["hint"] = hint_model

        # Peer d'abord : les métriques réelles (Retina) ne sont fiables qu'après.
        frame = self.uno_ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.uno_ctx).getCurrentFrame()
        parent_window = frame.getContainerWindow() if frame else None
        dialog.createPeer(toolkit, parent_window)

        self._layout()

        if parent_window is not None:
            try:
                ps = parent_window.getPosSize()
                dialog.setPosSize(ps.X + max(0, (ps.Width - self._width) // 2),
                                  ps.Y + max(0, (ps.Height - self._height) // 3),
                                  0, 0, 3)  # POS
            except Exception:
                pass

        key_handler = _KeyHandler(self._on_send, self.close)
        prompt_control.addKeyListener(key_handler)
        self._handlers.append(key_handler)

        self._render_conversation()

    # ── Layout mesuré ───────────────────────────────────────────────────
    def _preferred(self, name):
        try:
            return self.dialog.getControl(name).getPreferredSize()
        except Exception:
            return None

    def _place(self, name, x, y, w, h):
        control = self.dialog.getControl(name)
        if control is not None:
            control.setPosSize(int(x), int(y), int(w), int(h), 15)  # POSSIZE

    def _layout(self):
        """Positionne tout à partir des tailles réelles de rendu."""
        # Échelle dérivée de la hauteur réelle d'une chip (HiDPI-safe)
        chip_prefs = {}
        line_h = 18
        for name in self._chip_names:
            pref = self._preferred(name)
            if pref is not None:
                chip_prefs[name] = pref
                line_h = max(line_h, pref.Height)
        scale = max(1.0, line_h / 22.0)

        margin = int(14 * scale)
        gap = int(8 * scale)
        chip_h = int(line_h + 10 * scale)
        width = int(660 * scale)
        self._width = width

        # Bandeau
        header_pref = self._preferred("header")
        header_h = int((header_pref.Height if header_pref else 24) + 18 * scale)
        self._place("header", 0, 0, width, header_h)
        y = header_h + gap

        # Chips avec retour à la ligne, largeur = taille préférée + padding
        x = margin
        for name in self._chip_names:
            pref = chip_prefs.get(name)
            w = int((pref.Width if pref else 90) + 18 * scale)
            if x + w > width - margin and x > margin:
                x = margin
                y += chip_h + gap
            self._place(name, x, y, w, chip_h)
            x += w + gap
        y += chip_h + int(12 * scale)

        # Prompt (≈ 3 lignes de texte)
        prompt_h = int(line_h * 3 + 14 * scale)
        self._place("prompt", margin, y, width - 2 * margin, prompt_h)
        y += prompt_h + gap

        # Statut + bouton Envoyer (largeur mesurée)
        send_pref = self._preferred("send")
        send_w = int((send_pref.Width if send_pref else 100) + 30 * scale)
        send_h = int(line_h + 14 * scale)
        self._place("send", width - margin - send_w, y, send_w, send_h)
        self._place("status", margin, y + (send_h - line_h) // 2,
                    width - 2 * margin - send_w - gap, line_h)
        y += send_h + int(10 * scale)

        # Fil de conversation
        response_h = int(170 * scale)
        self._place("response", margin, y, width - 2 * margin, response_h)
        y += response_h + gap

        # Toggle + journal repliable
        toggle_pref = self._preferred("journal_toggle")
        toggle_w = int((toggle_pref.Width if toggle_pref else 140) + 10 * scale)
        self._place("journal_toggle", margin, y, toggle_w, line_h)
        y += line_h + int(4 * scale)
        if self.journal_visible:
            journal_h = int(90 * scale)
            self._place("journal", margin, y, width - 2 * margin, journal_h)
            self.dialog.getControl("journal").setVisible(True)
            y += journal_h + gap
        else:
            self.dialog.getControl("journal").setVisible(False)

        # Pied : liens mesurés + hint aligné à droite
        x = margin
        for name, _label, _cb in self._footer_specs:
            pref = self._preferred(name)
            w = int((pref.Width if pref else 90) + 6 * scale)
            self._place(name, x, y, w, line_h)
            x += w + int(14 * scale)
        hint_pref = self._preferred("hint")
        hint_w = int((hint_pref.Width if hint_pref else 90) + 6 * scale)
        hint_x = max(x, width - margin - hint_w)
        self._place("hint", hint_x, y, width - margin - hint_x, line_h)
        y += line_h + margin

        self._height = y
        ps = self.dialog.getPosSize()
        self.dialog.setPosSize(ps.X, ps.Y, width, self._height, 15)

    # ── Affichage ───────────────────────────────────────────────────────
    def show(self):
        self.dialog.setVisible(True)
        try:
            self.dialog.getControl("prompt").setFocus()
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
        self._layout()

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
