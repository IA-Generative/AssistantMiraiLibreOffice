"""Construction de la palette — le test qui manquait.

Une régression a échappé à 465 tests verts : `_layout()` lisait `self._width`
avant qu'il n'existe, et la palette ne s'ouvrait plus du tout. Aucun test ne
CONSTRUISAIT la palette — ils vérifiaient tous le moteur, jamais l'assemblage
de l'IHM.

Ces tests montent la palette complète sur des contrôles factices. Ils
n'inspectent pas le rendu (impossible hors LibreOffice) mais attrapent la
famille de pannes qui empêche l'ouverture : attribut manquant, appel de
méthode inexistante, mauvaise signature.
"""

from unittest.mock import MagicMock

import pytest

from tests.stubs.uno_stubs import install

install()


class FakeSize:
    def __init__(self, width=60, height=16):
        self.Width = width
        self.Height = height


class FakePosSize:
    X = 0
    Y = 0
    Width = 900
    Height = 700


class FakeControlModel:
    """Modèle de contrôle à état réel : `Text`/`Label` sont de vraies chaînes.

    Un MagicMock rendrait `.Text` incomparable, et masquerait les assertions
    portant sur le contenu affiché.
    """

    def __init__(self):
        self.Text = ""
        self.Label = ""
        self.TextColor = 0
        self.FontWeight = 100.0

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)


class FakeControl:
    """Contrôle UNO minimal : accepte tout, mesure une taille plausible."""

    def __init__(self, name):
        self.name = name
        self.visible = True
        self.model = FakeControlModel()
        self.listeners = []

    def setPosSize(self, *_args):
        pass

    def getPosSize(self):
        return FakePosSize()

    def getPreferredSize(self):
        return FakeSize()

    def getModel(self):
        return self.model

    def setVisible(self, value):
        self.visible = value

    def setFocus(self):
        pass

    def addMouseListener(self, listener):
        self.listeners.append(listener)

    def addKeyListener(self, listener):
        self.listeners.append(listener)

    def addItemListener(self, listener):
        self.listeners.append(listener)

    def setText(self, text):
        self.model.Text = text

    def isVisible(self):
        return self.visible


class FakeDialog:
    def __init__(self):
        self.controls = {}
        self.model = FakeDialogModel(self)
        self.top_listeners = []
        self.window_listeners = []
        self.visible = False

    def setModel(self, _model):
        pass

    def getControl(self, name):
        return self.controls.setdefault(name, FakeControl(name))

    def setVisible(self, value):
        self.visible = value

    def setTitle(self, _title):
        pass

    def setPosSize(self, *_args):
        pass

    def getPosSize(self):
        return FakePosSize()

    def createPeer(self, *_args):
        pass

    def addTopWindowListener(self, listener):
        self.top_listeners.append(listener)

    def removeTopWindowListener(self, listener):
        self.top_listeners.remove(listener)

    def addWindowListener(self, listener):
        self.window_listeners.append(listener)

    def dispose(self):
        pass

    def setFocus(self):
        pass


class FakeDialogModel:
    def __init__(self, dialog):
        self._dialog = dialog
        self.names = []

    def createInstance(self, _service):
        return FakeControlModel()

    def insertByName(self, name, model):
        self.names.append(name)
        # Le contrôle et son modèle doivent être le MÊME objet des deux côtés,
        # sinon une écriture via _models[...] ne se voit pas via getControl().
        control = self._dialog.getControl(name)
        control.model = model


@pytest.fixture
def palette_module(monkeypatch):
    from src.mirai.core.ui_thread import DirectDispatcher
    from src.mirai.ui import dsfr
    from src.mirai.ui import palette as palette_module

    dialog = FakeDialog()
    monkeypatch.setattr(dsfr, "make_dialog",
                        lambda *_a, **_k: (dialog, dialog.model))
    monkeypatch.setattr(dsfr, "probe_font", lambda _toolkit: "Arial")
    monkeypatch.setattr(palette_module, "_open_palette", [None])
    # Dispatcher SYNCHRONE : avec le vrai, le service AsyncCallback est un
    # MagicMock qui accepte les tâches sans jamais les exécuter — les
    # assertions porteraient alors sur un affichage jamais mis à jour.
    monkeypatch.setattr(palette_module, "MainThreadDispatcher",
                        lambda _ctx, log=None: DirectDispatcher())
    palette_module._fake_dialog = dialog
    return palette_module


def _build(palette_module, app="writer"):
    shell = MagicMock()
    shell.toolkit.return_value = MagicMock()
    shell.user_config_dir.return_value = "/tmp/mirai-test-palette"
    shell.get_config.side_effect = lambda key, default=None: default
    shell.log = lambda _m: None

    uno_ctx = MagicMock()
    return palette_module.AssistantPalette(uno_ctx, shell, app, callbacks={})


def test_palette_builds_for_writer(palette_module):
    """Le test qui aurait attrapé la régression : la palette se construit."""
    palette = _build(palette_module, "writer")
    assert palette.dialog is not None


def test_palette_builds_for_calc(palette_module):
    palette = _build(palette_module, "calc")
    assert palette.dialog is not None


def test_geometry_attributes_exist_before_layout(palette_module):
    """`_layout()` lit `_width` : il doit exister dès la construction."""
    palette = _build(palette_module)
    assert isinstance(palette._width, int)
    assert isinstance(palette._height, int)


def test_layout_can_be_rerun_with_an_imposed_width(palette_module):
    """Le redimensionnement passe par là — un TypeError ici gèle la fenêtre."""
    palette = _build(palette_module)
    palette._layout(width=1200)
    assert palette._width == 1200


def test_layout_is_idempotent(palette_module):
    """Invariant : relancer _layout() est toujours sûr (bascule d'onglet…)."""
    palette = _build(palette_module)
    first = palette._width
    palette._layout()
    palette._layout()
    assert palette._width == first


def test_all_three_tabs_are_created(palette_module):
    palette = _build(palette_module)
    assert palette.dialog is not None
    for tab_id, _label in palette_module.TABS:
        assert tab_id in palette._models, f"contenu manquant : {tab_id}"
        assert f"tab_{tab_id}" in palette._models, f"onglet manquant : {tab_id}"


def test_selecting_a_tab_does_not_raise(palette_module):
    palette = _build(palette_module)
    for tab_id, _label in palette_module.TABS:
        palette.select_tab(tab_id)
    assert palette.active_tab == palette_module.TABS[-1][0]


def test_footer_has_no_settings_links(palette_module):
    """Réglages / À propos / Documentation vivent UNIQUEMENT dans le menu."""
    _build(palette_module)
    names = set(palette_module._fake_dialog.model.names)
    for forbidden in ("link_settings", "link_about", "link_doc"):
        assert forbidden not in names, f"{forbidden} ne doit plus être dans la palette"
    assert "link_clear" in names


def test_resize_listener_is_attached(palette_module):
    palette = _build(palette_module)
    palette.show()
    dialog = palette_module._fake_dialog
    assert dialog.top_listeners, "la croix de fenêtre doit être écoutée"
    assert dialog.window_listeners, "le redimensionnement doit être écouté"


def test_close_removes_listeners_before_dispose(palette_module):
    """Retirer APRÈS dispose fait notifier un contrôle détruit."""
    palette = _build(palette_module)
    palette.show()
    palette.close()
    assert palette_module._fake_dialog.top_listeners == []


def test_conversation_shows_most_recent_first(palette_module):
    """Main courante : le dernier échange doit apparaître EN HAUT."""
    palette = _build(palette_module)
    palette.conversation.load = lambda: [
        {"role": "user", "text": "première question", "app": "writer"},
        {"role": "assistant", "text": "première réponse", "app": "writer"},
        {"role": "user", "text": "seconde question", "app": "writer"},
        {"role": "assistant", "text": "seconde réponse", "app": "writer"},
    ]
    palette.reload_history()

    text = palette._models["response"].Text
    assert text.index("seconde question") < text.index("première question"), (
        "l'échange le plus récent doit être en tête du fil")
    assert text.index("seconde question") < text.index("seconde réponse"), (
        "à l'intérieur d'un échange, la question précède la réponse")


def test_current_exchange_stays_on_top(palette_module):
    palette = _build(palette_module)
    palette.conversation.load = lambda: [
        {"role": "user", "text": "ancienne", "app": "writer"},
        {"role": "assistant", "text": "ancienne réponse", "app": "writer"},
    ]
    palette.reload_history()
    palette._append_response("Vous : ", "en cours")

    text = palette._models["response"].Text
    assert text.index("en cours") < text.index("ancienne")


# ── Mode « ajouter à la suite » ─────────────────────────────────────────

def test_append_mode_checkbox_exists(palette_module):
    """Les deux écoles coexistent : remplacer, ou ajouter entre marqueurs."""
    _build(palette_module)
    assert "append_mode" in palette_module._fake_dialog.model.names


def test_append_mode_defaults_to_replacing(palette_module):
    palette = _build(palette_module)
    assert palette.append_mode is False


def test_append_mode_is_remembered(palette_module):
    palette = _build(palette_module)
    palette.set_append_mode(True)

    assert palette.append_mode is True
    palette.shell.set_config.assert_called_with("assistant_append_mode", "1")


def test_sink_follows_the_choice(palette_module):
    from src.mirai.core.sinks import WriterInsertSink, WriterReplaceSink

    palette = _build(palette_module)
    ctx = MagicMock()

    palette.append_mode = False
    assert isinstance(palette._document_sink(ctx), WriterReplaceSink)

    palette.append_mode = True
    sink = palette._document_sink(ctx)
    assert isinstance(sink, WriterInsertSink)
    assert "début-du-texte-modifié" in sink.header_marker


# ── Journal d'actions ───────────────────────────────────────────────────

def test_journal_receives_lines_outside_agentic_mode(palette_module):
    """L'onglet Actions restait vide sur les presets et la réécriture."""
    palette = _build(palette_module)
    palette.journal_line("⚙ Lecture du document")
    palette.journal_line("✓ Écriture appliquée")

    text = palette._models["journal"].Text
    assert "Lecture du document" in text
    assert "Écriture appliquée" in text


def test_journal_lines_also_reach_the_log_file(palette_module):
    """Sans cela, un défaut rapporté ne laisse aucune trace de ce qu'a fait le run.

    Constaté le 2026-07-26 : `~/log.txt` ne portait que « run: début » et
    « run: terminé ». Impossible de dire quel chemin avait été emprunté, ni si
    le document avait été modifié — la seule information était à l'écran.
    """
    palette = _build(palette_module)
    written = []
    palette.shell.log = written.append

    palette.journal_line("✓ Lecture du document — 45 paragraphe(s)")

    assert any("Lecture du document — 45" in line for line in written)


def test_a_step_produces_telemetry_without_the_french_text(palette_module):
    from src.mirai.core import telemetry_steps

    palette = _build(palette_module)
    palette.shell.log = lambda _m: None
    palette.shell.telemetry.reset_mock()

    palette.journal_line("↳ Titre conservé : « Rapport annuel 2026 »",
                         step=telemetry_steps.DOCUMENT_READ,
                         **{"document.paragraphs": 45})

    name, attributes = palette.shell.telemetry.call_args[0]
    assert name == telemetry_steps.SPAN
    assert attributes["document.paragraphs"] == 45
    assert "Rapport annuel" not in str(attributes), "le document ne sort pas du poste"


def test_a_line_without_a_step_sends_no_telemetry(palette_module):
    """Toutes les lignes ne sont pas des étapes : pas de bruit dans les traces."""
    palette = _build(palette_module)
    palette.shell.log = lambda _m: None
    palette.shell.telemetry.reset_mock()

    palette.journal_line("↳ Titre conservé : « Rapport annuel 2026 »")

    palette.shell.telemetry.assert_not_called()


def test_text_is_written_through_the_control(palette_module):
    """Écrire le modèle ne repeint pas toujours : le contrôle doit suivre.

    Un UnoControlEdit déjà doté d'un peer conserve la donnée sans l'afficher —
    la zone paraît vide alors qu'une relecture du modèle rend bien le texte.
    """
    palette = _build(palette_module)
    palette._set_text("response", "bonjour")

    dialog = palette_module._fake_dialog
    assert palette._models["response"].Text == "bonjour"
    assert dialog.getControl("response").model.Text == "bonjour"


def test_set_text_tolerates_a_missing_control(palette_module):
    palette = _build(palette_module)
    palette._set_text("inexistant", "x")   # ne doit pas lever


# ── Panneau de réflexion (le « ⓘ ») ─────────────────────────────────────

def test_reasoning_pane_is_created_without_a_tab(palette_module):
    """Contenu de la zone basse, mais sans onglet : on y accède par le ⓘ."""
    _build(palette_module)
    names = palette_module._fake_dialog.model.names

    assert palette_module.REASONING_PANE in names
    assert "reasoning_toggle" in names
    assert f"tab_{palette_module.REASONING_PANE}" not in names


def test_toggle_opens_then_closes_and_restores_the_tab(palette_module):
    """Un clic ouvre et MAINTIENT ; un second revient d'où l'on vient."""
    palette = _build(palette_module)
    palette.select_tab("journal")

    palette.toggle_reasoning()
    assert palette.active_tab == palette_module.REASONING_PANE

    palette.toggle_reasoning()
    assert palette.active_tab == "journal"


def test_reasoning_pane_is_not_remembered_across_sessions(palette_module):
    """Rouvrir la palette sur un raisonnement périmé n'aurait aucun sens."""
    palette = _build(palette_module)
    palette.select_tab("response")
    palette.shell.set_config.reset_mock()

    palette.toggle_reasoning()

    saved = [c for c in palette.shell.set_config.call_args_list
             if c.args and c.args[0] == "assistant_active_tab"]
    assert saved == []


def test_marker_appears_only_when_there_is_something_to_read(palette_module):
    palette = _build(palette_module)

    palette.set_reasoning("le modèle réfléchit…")
    assert palette._models["reasoning_toggle"].Label == "ⓘ"
    assert "réfléchit" in palette._models[palette_module.REASONING_PANE].Text

    palette.set_reasoning("")
    assert palette._models["reasoning_toggle"].Label == ""
