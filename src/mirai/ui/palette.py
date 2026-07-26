"""Palette universelle MIrAI — fenêtre de prompt non modale, style DSFR.

Point d'entrée unique de l'assistant : prompt libre + chips des fonctions
fréquentes + fil de conversation persisté + journal d'actions optionnel
(séquence des outils proposés puis exécutés, façon agent).

Layout MESURÉ : les positions/tailles ne sont jamais estimées en pixels fixes
— après création du peer, chaque contrôle texte est dimensionné via
getPreferredSize() (tailles réelles de rendu, HiDPI/Retina compris) et le
reste est dérivé d'un facteur d'échelle. Invariant : relancer _layout() est
toujours sûr (repli du journal, etc.).

Threading : le run entier vit dans un thread worker ; le thread principal
retourne immédiatement à la boucle d'événements de LibreOffice, qui reste donc
utilisable pendant toute la génération (frappe, défilement, autre document).
Tout ce qui touche UNO — document, contrôles, undo — repasse par
`MainThreadDispatcher` (core/ui_thread.py). Le drapeau `busy` interdit deux
runs simultanés ; `_cancel` permet d'arrêter celui en cours.
"""

import threading
import time

import unohelper
from com.sun.star.awt import XKeyListener

try:
    from com.sun.star.awt import XCallback
except Exception:
    class XCallback:  # stub hors LO (tests)
        pass

try:
    from com.sun.star.view import XSelectionChangeListener as _XSelectionChangeListener
except Exception:
    _XSelectionChangeListener = None

try:
    from com.sun.star.awt import XTopWindowListener as _XTopWindowListener
except Exception:
    _XTopWindowListener = None

from ..core import presets as presets_module
from ..core import selection_info, suggestions
from ..core.context import ToolContext
from ..core.conversation import ConversationStore
from ..core.llm_client import LLMClient
from ..core.orchestrator import Orchestrator, RunObserver
from ..core.registry import ToolRegistry
from ..core.sinks import PaletteSink, WriterReplaceSink
from ..core.tools import register_all
from ..core.ui_thread import DispatcherClosed, MainThreadDispatcher
from . import dsfr

try:
    from com.sun.star.awt.Key import ESCAPE as KEY_ESCAPE
    from com.sun.star.awt.Key import RETURN as KEY_RETURN
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

FLUSH_INTERVAL_S = 0.12   # cadence maximale des mises à jour d'affichage
FLUSH_CHARS = 80          # ou dès qu'on a accumulé ce nombre de caractères

# Zone basse : trois contenus, un seul rectangle. L'identifiant sert aussi de
# nom de contrôle (« response » porte l'historique, déjà créé plus haut).
TABS = (("response", "Historique"),
        ("suggestions", "Suggestions"),
        ("journal", "Actions"))

# Le retour d'un run doit se VOIR : une ligne de statut colorée selon l'issue,
# pas un texte discret dans une zone grise. C'est la leçon du « il ne se passe
# rien » — l'action partait bien, mais rien ne le signalait à l'écran.
STATUS_COLORS = {
    "neutral": dsfr.TOKENS["text_mention"],
    "error":   dsfr.TOKENS["error"],
    "success": dsfr.TOKENS["success"],
}


class _WindowCloser(unohelper.Base,
                    *([_XTopWindowListener] if _XTopWindowListener else [])):
    """Ferme la palette quand l'utilisateur clique la croix de la fenêtre.

    Un `UnoControlDialog` non modal ne se ferme PAS tout seul : la croix émet
    `windowClosing` et attend que quelqu'un agisse. Sans ce listener, le bouton
    de fermeture est inopérant — la fenêtre reste à l'écran quoi qu'on fasse.

    `windowActivated` sert de filet à l'indicateur de sélection : en Writer le
    listener de sélection ne se déclenche pas toujours sur un simple
    déplacement du curseur ; revenir sur la palette relit la cible.
    """

    def __init__(self, palette):
        self._palette = palette

    def windowClosing(self, _event):
        self._palette.close()

    def windowActivated(self, _event):
        self._palette.refresh_selection_label()

    # Le reste de l'interface : rien à faire, mais UNO exige les méthodes.
    def windowOpened(self, _event):
        pass

    def windowClosed(self, _event):
        pass

    def windowMinimized(self, _event):
        pass

    def windowNormalized(self, _event):
        pass

    def windowDeactivated(self, _event):
        pass

    def disposing(self, _event):
        pass


try:
    from com.sun.star.awt import XWindowListener as _XWindowListener
except Exception:
    _XWindowListener = None


class _ResizeWatcher(unohelper.Base,
                     *([_XWindowListener] if _XWindowListener else [])):
    """Relance le layout sur la taille RÉELLE du peer après redimensionnement.

    Sans cela, `Sizeable` agrandit le cadre mais les contrôles restent à leur
    place : la fenêtre grandit, son contenu non.
    """

    def __init__(self, palette):
        self._palette = palette

    def windowResized(self, event):
        self._palette.on_resized(event.Width, event.Height)

    def windowMoved(self, _event):
        pass

    def windowShown(self, _event):
        pass

    def windowHidden(self, _event):
        pass

    def disposing(self, _event):
        pass


class _SelectionWatcher(unohelper.Base,
                        *([_XSelectionChangeListener]
                          if _XSelectionChangeListener else [])):
    """Suit la sélection du document — en PUSH, jamais en polling.

    LibreOffice livre `selectionChanged` sur le thread principal : on peut donc
    écrire dans les contrôles depuis le callback sans marshalling. C'est ce qui
    distingue ce patron du thread de rafraîchissement du code historique, qui
    écrivait dans des contrôles VCL toutes les 3 s depuis un thread de fond,
    sans SolarMutex.
    """

    def __init__(self, palette):
        self._palette = palette

    def selectionChanged(self, _event):
        self._palette.refresh_selection_label()

    def disposing(self, _event):
        self._palette.detach_selection_watcher()


def _selection_string(ctx):
    """Texte sélectionné, ou chaîne vide. À n'appeler que sur le thread principal."""
    try:
        return ctx.controller.getSelection().getByIndex(0).getString()
    except Exception:
        return ""


def _writer_targets(model):
    """(texte sélectionné, texte du paragraphe courant) — jamais d'exception.

    Sans sélection les actions ciblent le paragraphe sous le curseur : il faut
    donc pouvoir l'afficher, sinon l'indicateur laisse croire qu'aucune cible
    n'est déterminée.
    """
    selected = paragraph = ""
    try:
        selected = model.CurrentController.getSelection().getByIndex(0).getString()
    except Exception:
        selected = ""
    if not selected.strip():
        try:
            view_cursor = model.CurrentController.getViewCursor()
            text = view_cursor.getText()
            cursor = text.createTextCursorByRange(view_cursor)
            cursor.gotoStartOfParagraph(False)
            cursor.gotoEndOfParagraph(True)
            paragraph = cursor.getString()
        except Exception:
            paragraph = ""
    return selected, paragraph


def _calc_selection_sample(model, max_values=40):
    """(nombre de cellules, échantillon de valeurs) — jamais d'exception."""
    try:
        selection = model.CurrentController.Selection
        area = selection.getRangeAddress()
        rows = abs(area.EndRow - area.StartRow) + 1
        cols = abs(area.EndColumn - area.StartColumn) + 1
        sheet = model.CurrentController.ActiveSheet
        values = []
        for row in range(area.StartRow, area.EndRow + 1):
            for col in range(area.StartColumn, area.EndColumn + 1):
                if len(values) >= max_values:
                    return rows * cols, values
                text = sheet.getCellByPosition(col, row).getString()
                if text:
                    values.append(text)
        return rows * cols, values
    except Exception:
        return 0, []


def _friendly_error(exc):
    """Traduit une panne technique en phrase actionnable pour l'utilisateur."""
    text = str(exc)
    if "401" in text or "Unauthorized" in text or "Missing credentials" in text:
        return ("Jeton expiré — Menu MIrAI ▸ Paramètres pour vous reconnecter.")
    if "timeout" in text.lower() or "timed out" in text.lower():
        return "Le service n'a pas répondu à temps. Réessayez dans un instant."
    if "thread principal n'a pas répondu" in text:
        return "LibreOffice était occupé (fenêtre ouverte ?). Réessayez."
    return f"Erreur : {text}"


class _DeltaCoalescer:
    """Regroupe les fragments du flux avant de les envoyer au thread principal.

    Sans ce tampon, un flux rapide poste un événement UNO par token et sature
    la file du thread principal — l'application redevient molle alors même
    qu'on vient de la libérer. On ne publie donc qu'au plus toutes les
    ~120 ms, ou dès ~80 caractères accumulés.
    """

    def __init__(self, flush):
        self._flush = flush
        self._pending = []
        self._chars = 0
        self._last_flush = 0.0

    def add(self, text):
        if not text:
            return
        self._pending.append(text)
        self._chars += len(text)
        now = time.monotonic()
        if self._chars >= FLUSH_CHARS or (now - self._last_flush) >= FLUSH_INTERVAL_S:
            self.flush(now)

    def flush(self, now=None):
        """Publie ce qui est en attente. Sûr même si rien n'a été accumulé."""
        if not self._pending:
            return
        text = "".join(self._pending)
        self._pending = []
        self._chars = 0
        self._last_flush = now if now is not None else time.monotonic()
        self._flush(text)

    def reset(self):
        self._pending = []
        self._chars = 0
        self._last_flush = 0.0


class _DeferredCall(unohelper.Base, XCallback):
    """Exécute fn dans un événement utilisateur PROPRE (AsyncCallback).

    INVARIANT : ne jamais lancer un run LLM directement depuis un listener
    souris/clavier — le pompage processEventsToIdle depuis un dispatch
    imbriqué gèle l'UI et peut aborter LibreOffice (std::terminate dans
    DispatchUserEvents). On sort du dispatch courant avant de travailler.
    """

    def __init__(self, fn):
        self._fn = fn

    def notify(self, data):
        try:
            self._fn()
        except Exception:
            pass


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
        self.active_tab = self._restore_tab(shell)
        self._bottom_height = 0        # ajusté par le redimensionnement
        self._base_bottom_h = 0        # hauteur de zone basse au premier layout
        self._natural_height = 0       # hauteur totale au premier layout
        self._min_width = 0            # largeur qui garde les chips sur UNE ligne
        self._scale = 1.0
        self._laying_out = False       # garde anti-réentrance (_layout → setPosSize)
        self._resize_watcher = None
        self.registry = register_all(ToolRegistry())
        self.conversation = ConversationStore(shell.user_config_dir())
        self.dialog = None
        self._models = {}
        self._handlers = []                 # garde les listeners vivants (GC)
        self._chip_names = []
        # Exécution non bloquante : le run vit dans un worker, tout ce qui
        # touche UNO repasse par le dispatcher (voir core/ui_thread.py).
        self.dispatcher = MainThreadDispatcher(uno_ctx, log=shell.log)
        self._worker = None
        self._cancel = None
        self._delta_buffer = _DeltaCoalescer(self._flush_deltas)
        self._selection_watcher = None      # (listener, contrôleur) — garde vivante
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
                "FontName": font, "FontHeight": 7, "FontWeight": 150.0,
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

        # Indicateur de sélection : ce sur quoi l'action va porter, en direct.
        _, selection_model = dsfr.add_control(
            dialog, model, "selection", "FixedText", 0, 0, 100, 18, {
                "Label": "",
                "TextColor": dsfr.TOKENS["text_mention"],
                "FontName": font, "FontHeight": 7,
            })
        self._models["selection"] = selection_model

        prompt_control, prompt_model = dsfr.add_control(
            dialog, model, "prompt", "Edit", 0, 0, 100, 56, {
                "MultiLine": True, "AutoVScroll": True,
                "FontName": font, "FontHeight": 7,
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
                "FontName": font, "FontHeight": 7,
            })
        self._models["status"] = status_model

        _, send_model = dsfr.add_primary_button(
            dialog, model, "send", "Envoyer  ⏎", 0, 0, 120, 32, font,
            self._on_send)
        self._models["send"] = send_model

        _, response_model = dsfr.add_control(
            dialog, model, "response", "Edit", 0, 0, 100, 200, {
                "MultiLine": True, "ReadOnly": True, "VScroll": True,
                "FontName": font, "FontHeight": 7,
                "TextColor": dsfr.TOKENS["text_body"],
                "BackgroundColor": dsfr.TOKENS["bg_alt"],
                "Border": 2, "BorderColor": dsfr.TOKENS["border"],
            })
        self._models["response"] = response_model

        # Zone basse : UN seul rectangle, trois contenus superposés qu'on
        # bascule par setVisible(). Réempiler trois zones distinctes ferait
        # exploser la hauteur — c'est justement ce qu'on corrige ici.
        for name, color, background in (
            ("suggestions", dsfr.TOKENS["text_body"], dsfr.TOKENS["bg_accent"]),
            ("journal", dsfr.TOKENS["text_mention"], dsfr.TOKENS["bg_accent"]),
        ):
            control, control_model = dsfr.add_control(
                dialog, model, name, "Edit", 0, 0, 100, 100, {
                    "MultiLine": True, "ReadOnly": True, "VScroll": True,
                    "FontName": font, "FontHeight": 7,
                    "TextColor": color, "BackgroundColor": background,
                    "Border": 2, "BorderColor": dsfr.TOKENS["border"],
                })
            self._models[name] = control_model
            control.setVisible(False)

        # Onglets : des FixedText cliquables (pas de UnoControlTabPageContainer,
        # capricieux et peu stylable). L'onglet actif porte la couleur accent.
        for tab_id, label in TABS:
            name = f"tab_{tab_id}"
            control, tab_model = dsfr.add_control(
                dialog, model, name, "FixedText", 0, 0, 90, 16, {
                    "Label": label,
                    "TextColor": dsfr.TOKENS["text_mention"],
                    "FontName": font, "FontHeight": 7,
                })
            self._models[name] = tab_model
            handler = dsfr.ClickHandler(
                tab_model, on_click=(lambda t=tab_id: self.select_tab(t)),
                fg=dsfr.TOKENS["text_mention"], fg_hover=dsfr.TOKENS["primary_hover"])
            control.addMouseListener(handler)
            self._handlers.append(handler)

        # Réglages / À propos / Documentation vivent UNIQUEMENT dans le menu
        # 🤖 MIrAI : la fenêtre ne garde que ce qui sert à travailler.
        dsfr.add_link(dialog, model, "link_clear", "🗑 Nouvelle conversation",
                      0, 0, 120, 16, font, self._on_clear)
        _, hint_model = dsfr.add_control(
            dialog, model, "hint", "FixedText", 0, 0, 120, 16, {
                "Label": "Entrée : envoyer · Échap : fermer",
                "TextColor": dsfr.TOKENS["text_mention"],
                "FontName": font, "FontHeight": 6, "Align": 2,
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

        # Échap doit fermer quel que soit le contrôle qui a le focus : le
        # brancher sur le seul champ de prompt laissait la fenêtre coincée dès
        # que le focus était ailleurs (une chip, la zone de réponse…).
        escape_handler = _KeyHandler(lambda: None, self.close)
        self._handlers.append(escape_handler)
        for name in ("response", "journal", "send", *self._chip_names):
            try:
                dialog.getControl(name).addKeyListener(escape_handler)
            except Exception:
                pass          # contrôle absent selon l'application — sans gravité

        # La croix de la fenêtre : sans listener, elle ne ferme RIEN.
        self._attach_window_closer()

        self._render_conversation()

    def _attach_window_closer(self):
        """Branche fermeture et redimensionnement sur le peer (après createPeer)."""
        if _XTopWindowListener is not None:
            try:
                closer = _WindowCloser(self)
                self.dialog.addTopWindowListener(closer)
                self._handlers.append(closer)   # référence vivante (GC)
                self._window_closer = closer
            except Exception as exc:
                self.shell.log(f"[palette] listener de fenêtre indisponible : {exc}")
        if _XWindowListener is not None:
            try:
                resizer = _ResizeWatcher(self)
                self.dialog.addWindowListener(resizer)
                self._handlers.append(resizer)
                self._resize_watcher = resizer
            except Exception as exc:
                self.shell.log(f"[palette] redimensionnement indisponible : {exc}")

    # ── Redimensionnement ───────────────────────────────────────────────

    def on_resized(self, width, height):
        """Réagit à un redimensionnement : toute la hauteur gagnée va en bas.

        Les bornes empêchent d'écraser la ligne de chips (largeur minimale
        calculée au premier layout) ou de faire disparaître la zone basse.
        """
        if self._laying_out:
            return                     # _layout() appelle setPosSize : pas de boucle
        width = max(width, self._min_width or 0)
        extra = height - self._natural_height
        self._bottom_height = max(int(70 * self._scale), self._base_bottom_h + extra)
        self._width = width
        self._laying_out = True
        try:
            self._layout(width=width)
        finally:
            self._laying_out = False
        self._save_geometry()

    def _save_geometry(self):
        """Mémorise position et taille pour la prochaine ouverture."""
        try:
            ps = self.dialog.getPosSize()
            self.shell.set_config(
                "assistant_window_rect", f"{ps.X},{ps.Y},{ps.Width},{ps.Height}")
        except Exception:
            pass          # préférence d'affichage : jamais bloquant

    def _restore_geometry(self):
        """Restaure la géométrie mémorisée, si elle est encore plausible."""
        try:
            raw = str(self.shell.get_config("assistant_window_rect", "") or "")
            x, y, width, height = (int(part) for part in raw.split(","))
        except Exception:
            return
        if width < 200 or height < 150:
            return                     # valeur aberrante : on garde le défaut
        try:
            self.dialog.setPosSize(x, y, width, height, 15)
            self.on_resized(width, height)
        except Exception:
            pass

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
        scale = min(max(1.0, line_h / 16.0), 2.0)

        margin = int(10 * scale)
        gap = int(6 * scale)
        chip_h = int(line_h + 6 * scale)
        width = int(500 * scale)
        self._width = width

        # Bandeau
        header_pref = self._preferred("header")
        header_h = int((header_pref.Height if header_pref else 20) + 10 * scale)
        self._place("header", 0, 0, width, header_h)
        y = header_h + gap

        # Chips avec retour à la ligne, largeur = taille préférée + padding
        x = margin
        for name in self._chip_names:
            pref = chip_prefs.get(name)
            w = int((pref.Width if pref else 90) + 12 * scale)
            if x + w > width - margin and x > margin:
                x = margin
                y += chip_h + gap
            self._place(name, x, y, w, chip_h)
            x += w + gap
        y += chip_h + int(8 * scale)

        # Indicateur de sélection — sous les chips, au-dessus du prompt : c'est
        # la réponse au « sur quoi ça va porter ? » posée avant de cliquer.
        selection_h = int(line_h + 2 * scale)
        self._place("selection", margin, y, width - 2 * margin, selection_h)
        y += selection_h + int(4 * scale)

        # Prompt (≈ 3 lignes de texte)
        prompt_h = int(line_h * 2 + 12 * scale)
        self._place("prompt", margin, y, width - 2 * margin, prompt_h)
        y += prompt_h + gap

        # Statut + bouton Envoyer (largeur mesurée)
        send_pref = self._preferred("send")
        send_w = int((send_pref.Width if send_pref else 100) + 22 * scale)
        send_h = int(line_h + 10 * scale)
        self._place("send", width - margin - send_w, y, send_w, send_h)
        self._place("status", margin, y + (send_h - line_h) // 2,
                    width - 2 * margin - send_w - gap, line_h)
        y += send_h + int(8 * scale)

        # Zone basse : les trois contenus occupent EXACTEMENT le même
        # rectangle ; seul l'onglet actif est visible. Toute la hauteur gagnée
        # au redimensionnement lui revient — le reste garde sa taille.
        bottom_h = max(int(70 * scale), self._bottom_height or int(120 * scale))
        for tab_id, _label in TABS:
            self._place(tab_id, margin, y, width - 2 * margin, bottom_h)
            try:
                self.dialog.getControl(tab_id).setVisible(tab_id == self.active_tab)
            except Exception:
                pass
        y += bottom_h + int(4 * scale)

        # Onglets en bas à gauche, « Nouvelle conversation » et hint à droite.
        x = margin
        for tab_id, _label in TABS:
            name = f"tab_{tab_id}"
            pref = self._preferred(name)
            w = int((pref.Width if pref else 70) + 8 * scale)
            self._place(name, x, y, w, line_h)
            x += w + int(8 * scale)
        clear_pref = self._preferred("link_clear")
        clear_w = int((clear_pref.Width if clear_pref else 120) + 6 * scale)
        self._place("link_clear", max(x, width - margin - clear_w), y, clear_w, line_h)
        y += line_h + int(4 * scale)

        hint_pref = self._preferred("hint")
        hint_w = int((hint_pref.Width if hint_pref else 90) + 6 * scale)
        self._place("hint", width - margin - hint_w, y, hint_w, line_h)
        y += line_h + margin

        self._height = y
        self._scale = scale
        if not self._natural_height:
            # Premier layout : il fixe les bornes du redimensionnement.
            self._natural_height = y
            self._base_bottom_h = bottom_h
            self._min_width = width
        ps = self.dialog.getPosSize()
        self.dialog.setPosSize(ps.X, ps.Y, width, self._height, 15)

    # ── Affichage ───────────────────────────────────────────────────────
    def show(self):
        self.dialog.setVisible(True)
        try:
            self.dialog.getControl("prompt").setFocus()
        except Exception:
            pass
        # Après createPeer : le contrôleur est prêt à accepter un listener.
        self.attach_selection_watcher()
        self.refresh_selection_label()
        self.select_tab(self.active_tab)
        self._restore_geometry()

    def close(self):
        """Ferme la palette et neutralise tout run encore en vol.

        L'ordre compte : on annule d'abord, on rend le dispatcher inerte
        ensuite, et seulement après on dispose. Un worker qui se réveille
        pendant la fermeture reçoit DispatcherClosed au lieu de toucher un
        contrôle détruit.
        """
        if self._cancel is not None:
            self._cancel.set()
        # Retirer les listeners AVANT dispose() : l'ordre inverse laisse
        # LibreOffice notifier un contrôle détruit.
        self.detach_selection_watcher()
        closer = getattr(self, "_window_closer", None)
        if closer is not None:
            self._window_closer = None
            try:
                self.dialog.removeTopWindowListener(closer)
            except Exception:
                pass          # peer déjà parti : rien à retirer
        self.dispatcher.close()
        try:
            self.dialog.setVisible(False)
            self.dialog.dispose()
        except Exception:
            pass
        if _open_palette[0] is self:
            _open_palette[0] = None

    # ── Mises à jour d'affichage ────────────────────────────────────────
    # Ces méthodes sont appelées indifféremment depuis le thread principal et
    # depuis le worker : elles postent systématiquement, ce qui garantit que
    # l'écriture dans les contrôles VCL a bien lieu sur le thread principal.

    def set_status(self, message, tone="neutral"):
        """Ligne de statut, colorée selon l'issue — le retour doit se VOIR."""
        def _apply():
            self._models["status"].Label = message
            self._models["status"].TextColor = STATUS_COLORS.get(
                tone, STATUS_COLORS["neutral"])
        self.dispatcher.post(_apply)

    def set_journal_text(self, text):
        self.dispatcher.post(lambda: self._models["journal"].__setattr__("Text", text))

    # ── Indicateur de sélection ─────────────────────────────────────────

    def attach_selection_watcher(self):
        """Branche le listener sur le contrôleur courant. Après createPeer."""
        if _XSelectionChangeListener is None:
            return
        try:
            controller = self._current_controller()
            if controller is None:
                return
            watcher = _SelectionWatcher(self)
            controller.addSelectionChangeListener(watcher)
            # Le couple est conservé sur l'instance : sans référence vivante le
            # ramasse-miettes emporterait le listener et les événements
            # cesseraient silencieusement.
            self._selection_watcher = (watcher, controller)
        except Exception as exc:
            self.shell.log(f"[palette] listener de sélection indisponible : {exc}")

    def detach_selection_watcher(self):
        """Retire le listener. À appeler AVANT dispose() — le legacy fait
        l'inverse et ne survit que grâce à un try/except."""
        pair = getattr(self, "_selection_watcher", None)
        if not pair:
            return
        watcher, controller = pair
        self._selection_watcher = None
        try:
            controller.removeSelectionChangeListener(watcher)
        except Exception as exc:
            self.shell.log(f"[palette] retrait du listener : {exc}")

    def _current_controller(self):
        desktop = self.uno_ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.uno_ctx)
        model = desktop.getCurrentComponent()
        return getattr(model, "CurrentController", None) if model else None

    def refresh_selection_label(self):
        """Recalcule le libellé de cible. Thread principal uniquement."""
        if self.busy:
            return
        try:
            self._models["selection"].Label = self._describe_selection()
        except Exception:
            pass          # contrôle disposé : la palette se ferme, rien à signaler

    def _describe_selection(self):
        """Décrit la cible courante ; ne rend JAMAIS None ni ne lève."""
        try:
            desktop = self.uno_ctx.getServiceManager().createInstanceWithContext(
                "com.sun.star.frame.Desktop", self.uno_ctx)
            model = desktop.getCurrentComponent()
            if model is None:
                return ""
            if hasattr(model, "Text"):
                return selection_info.writer_label(*_writer_targets(model))
            if hasattr(model, "Sheets"):
                area = model.CurrentController.Selection.getRangeAddress()
                return selection_info.calc_label(
                    area.StartColumn, area.StartRow, area.EndColumn, area.EndRow)
        except Exception:
            pass
        return ""

    # ── Zone basse à onglets ────────────────────────────────────────────

    @staticmethod
    def _restore_tab(shell):
        """Onglet actif de la session précédente, « Historique » par défaut."""
        try:
            stored = str(shell.get_config("assistant_active_tab", "") or "")
        except Exception:
            stored = ""
        return stored if stored in dict(TABS) else "response"

    def select_tab(self, tab_id):
        """Bascule la zone basse. L'onglet actif est mémorisé en configuration."""
        if tab_id not in dict(TABS):
            return
        self.active_tab = tab_id
        if tab_id == "suggestions":
            self.refresh_suggestions()
        for other, _label in TABS:
            model = self._models.get(f"tab_{other}")
            if model is None:
                continue
            active = other == tab_id
            model.TextColor = (dsfr.TOKENS["primary"] if active
                               else dsfr.TOKENS["text_mention"])
            model.FontWeight = 150.0 if active else 100.0
        try:
            self.shell.set_config("assistant_active_tab", tab_id)
        except Exception:
            pass          # préférence d'affichage : jamais bloquant
        self._layout()

    def refresh_suggestions(self):
        """Recalcule les propositions pour la cible courante."""
        try:
            self._models["suggestions"].Text = suggestions.render(
                self._current_suggestions())
        except Exception as exc:
            self.shell.log(f"[palette] suggestions indisponibles : {exc}")

    def _current_suggestions(self):
        """Décrit la situation au moteur de suggestions (aucun appel LLM)."""
        desktop = self.uno_ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.uno_ctx)
        model = desktop.getCurrentComponent()
        if model is None:
            return suggestions.suggest(self.app)
        if hasattr(model, "Text"):
            selected, paragraph = _writer_targets(model)
            return suggestions.suggest(
                "writer", selected_text=selected, has_paragraph=bool(paragraph.strip()))
        if hasattr(model, "Sheets"):
            count, values = _calc_selection_sample(model)
            return suggestions.suggest("calc", cell_count=count, values=values)
        return suggestions.suggest(self.app)

    def _render_conversation(self):
        entries = self.conversation.load()
        lines = []
        for entry in entries:
            prefix = "Vous : " if entry["role"] == "user" else "MIrAI : "
            lines.append(prefix + entry["text"])
        self._models["response"].Text = "\n\n".join(lines)

    def _append_response(self, prefix, text=""):
        def _apply():
            current = self._models["response"].Text
            addition = (prefix + text) if text or prefix else ""
            self._models["response"].Text = (
                (current + "\n\n" + addition) if current else addition)
        self.dispatcher.post(_apply)

    def _stream_response(self, chunk):
        """Entrée du flux : on accumule, le tampon décide quand publier."""
        self._delta_buffer.add(chunk)

    def _flush_deltas(self, text):
        def _apply():
            self._models["response"].Text = self._models["response"].Text + text
        self.dispatcher.post(_apply)

    def _on_clear(self):
        if self.busy:
            return
        self.conversation.clear()
        self._models["response"].Text = ""
        self.set_journal_text("")
        self.set_status("Conversation effacée.")

    # ── Exécution ───────────────────────────────────────────────────────
    def _current_context(self):
        """Résout le document courant. À appeler depuis le thread principal.

        Le document est re-résolu à chaque run plutôt que mémorisé à
        l'ouverture : l'utilisateur peut avoir changé d'onglet entre-temps.
        Le contexte porte le dispatcher — c'est par lui que les tools et les
        sinks remonteront sur le thread principal depuis le worker.
        """
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
                           app, self.shell, dispatcher=self.dispatcher)

    def _prompt_text(self):
        try:
            return str(self._models["prompt"].Text or "")
        except Exception:
            return ""

    def _defer(self, fn):
        """Planifie fn hors du dispatch d'événement courant (voir _DeferredCall)."""
        try:
            async_callback = self.uno_ctx.getServiceManager() \
                .createInstanceWithContext("com.sun.star.awt.AsyncCallback",
                                           self.uno_ctx)
            deferred = _DeferredCall(fn)
            self._handlers.append(deferred)   # référence vivante jusqu'au notify
            async_callback.addCallback(deferred, None)
        except Exception:
            fn()   # repli : exécution directe (mieux que rien)

    def _on_chip(self, preset):
        if self.busy:
            return
        self._defer(lambda: self._start_run(preset=preset))

    def _on_send(self):
        """Envoyer, ou Arrêter si un run est déjà en cours."""
        if self.busy:
            self._cancel_run()
            return
        self._defer(lambda: self._start_run(preset=None))

    def _cancel_run(self):
        """Demande l'arrêt du run en cours. Le worker s'arrête entre deux chunks."""
        if self._cancel is not None:
            self._cancel.set()
            self.set_status("Arrêt en cours…")

    def _start_run(self, preset=None):
        """Valide la demande sur le thread principal, puis lance le worker.

        Les contrôles préalables (prompt vide, type de document) lisent l'UI et
        le document : ils doivent rester ici. Dès que la demande est valide, la
        main est rendue à LibreOffice et tout le travail part dans le worker.
        """
        if self.busy:
            return
        prompt_text = self._prompt_text().strip()
        if preset is None and not prompt_text:
            self.set_status("Tapez d'abord votre demande.", tone="error")
            return
        if preset is not None and preset.needs_input and not prompt_text:
            self.set_status(preset.input_hint or "Précisez votre demande.",
                            tone="error")
            return

        ctx = self._current_context()
        if ctx is None:
            self.set_status("Ouvrez un document Writer ou Calc.", tone="error")
            return
        if preset is not None and ctx.app not in preset.apps:
            wanted = "Writer" if "writer" in preset.apps else "Calc"
            self.set_status(f"Cette action nécessite un document {wanted}.",
                            tone="error")
            return

        self.busy = True
        self._cancel = threading.Event()
        self._delta_buffer.reset()
        self._set_send_label(running=True)
        # La réponse arrive dans l'Historique : si l'utilisateur regarde un
        # autre onglet, il ne verrait RIEN se produire. On bascule donc pour lui.
        if self.active_tab != "response":
            self.select_tab("response")
        self.set_status("L'assistant travaille…")
        shown = prompt_text if preset is None else (
            preset.label + ((" — " + prompt_text) if prompt_text else ""))
        self._append_response("Vous : ", shown)

        self._worker = threading.Thread(
            target=self._run_in_worker,
            args=(preset, prompt_text, ctx, shown),
            daemon=True, name="mirai-run")
        self._worker.start()

    def _run_in_worker(self, preset, prompt_text, ctx, shown):
        """Corps du run — s'exécute HORS du thread principal.

        Aucun accès direct à l'UI ni au document ici : tout passe par
        `self.dispatcher` (post pour l'affichage, call pour le document).
        """
        try:
            if preset is not None and preset.mode == "pipeline":
                self._run_pipeline(preset, prompt_text, ctx, shown)
            else:
                self._run_agentic(preset, prompt_text, ctx)
            self._delta_buffer.flush()
            self._finish_run()
        except DispatcherClosed:
            self.shell.log("[palette] run interrompu : palette fermée")
        except Exception as exc:
            self.shell.log(f"[palette] run error: {exc}")
            self._delta_buffer.flush()
            self.set_status(_friendly_error(exc), tone="error")
            self._append_response("MIrAI : ", f"⚠ {_friendly_error(exc)}")
        finally:
            self.busy = False
            self._cancel = None
            self._worker = None
            self._set_send_label(running=False)

    def _run_pipeline(self, preset, prompt_text, ctx, shown):
        """Preset piloté par Python : le LLM n'est qu'une fonction texte.

        Le runner touche le document ; il le fait via ctx.on_main. Son appel LLM
        reste dans ce worker.
        """
        message = preset.runner(ctx, self.shell, prompt_text, None,
                                cancel_event=self._cancel,
                                dispatcher=self.dispatcher)
        self._append_response("MIrAI : ", message)
        self.conversation.append("user", shown, ctx.app)
        self.conversation.append("assistant", message, ctx.app)

    def _run_agentic(self, preset, prompt_text, ctx):
        """Run piloté par le LLM, qui appelle les outils du registre."""
        orchestrator = Orchestrator(
            LLMClient(self.shell), self.registry, ctx,
            observer=_JournalObserver(self),
            conversation=self.conversation,
            cancel_event=self._cancel,
            dispatcher=self.dispatcher)

        extra, user_prompt, sink = self._prepare_agentic_run(preset, prompt_text, ctx)
        self._append_response("MIrAI : ")
        result = orchestrator.run_agentic(
            user_prompt, sink, preset_extra=extra,
            preset_id=preset.id if preset else "free")
        self._delta_buffer.flush()
        if not result.ok:
            self._stream_response("⚠ " + (result.text or result.reason))
        elif not isinstance(sink, PaletteSink):
            self._stream_response(result.text or "Modification appliquée.")

    def _prepare_agentic_run(self, preset, prompt_text, ctx):
        """Résout prompt, contexte supplémentaire et destination de la sortie."""
        extra = ""
        user_prompt = prompt_text
        sink = None
        if preset is not None:
            if preset.build_extra:
                extra = preset.build_extra(ctx, self.shell, prompt_text)
            if preset.prompt_template:
                user_prompt = preset.prompt_template(prompt_text)
            if preset.sink_spec == "auto_edit":
                # Lecture du document → thread principal obligatoire.
                selection = self.dispatcher.call(
                    lambda: _selection_string(ctx), timeout=10)
                if selection.strip():
                    sink = WriterReplaceSink(ctx)
        if sink is None:
            sink = PaletteSink(on_delta=self._stream_response)
        return extra, user_prompt, sink

    def _finish_run(self):
        """Statut de fin : arrêté, ou terminé avec le champ de prompt vidé."""
        if self._cancelled():
            self.set_status("Arrêté.", tone="neutral")
            return
        self.dispatcher.post(
            lambda: self._models["prompt"].__setattr__("Text", ""))
        self.set_status("Terminé", tone="success")

    def _set_send_label(self, running):
        """Bascule Envoyer ⇄ Arrêter.

        Toujours par le dispatcher, même depuis le thread principal : mélanger
        écriture directe et écriture postée fait diverger l'affichage de l'état
        réel — le bouton restait sur « Arrêter » après la fin du run.
        """
        label = "Arrêter" if running else "Envoyer  ⏎"
        self.dispatcher.post(
            lambda: self._models["send"].__setattr__("Label", label))

    def _cancelled(self):
        return self._cancel is not None and self._cancel.is_set()


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
