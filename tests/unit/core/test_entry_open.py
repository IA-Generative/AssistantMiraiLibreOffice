"""AssistantOpen enrichi : état de la sélection + verdict de capacités.

Le verdict mesuré (menu « Tester le modèle ») décide du chemin d'exécution du
prompt libre Writer — et son défaut prudent est NON : sur un poste jamais
sondé, le mode agentique est inaccessible. Sans `caps.measured` à l'ouverture,
impossible de savoir quelle part du parc travaille en mode dégradé faute
d'avoir lancé la sonde une seule fois.
"""

from src.mirai.core import capabilities
from src.mirai.core.entry import _open_attributes
from tests.stubs.fake_shell import FakeShell


class _Selection:
    def __init__(self, text):
        self._text = text

    def getByIndex(self, _index):
        return self

    def getString(self):
        return self._text


class _WriterModel:
    def __init__(self, selection_text=""):
        self.Text = object()

        class _Controller:
            def getSelection(_self):
                return _Selection(selection_text)

        self.CurrentController = _Controller()


class _BrokenModel:
    Text = object()

    @property
    def CurrentController(self):
        raise RuntimeError("contrôleur indisponible")


def test_an_active_selection_is_reported():
    attrs = _open_attributes(FakeShell(), _WriterModel("du texte"), "writer")
    assert attrs["assistant.app"] == "writer"
    assert attrs["selection.active"] is True


def test_an_empty_selection_is_reported():
    attrs = _open_attributes(FakeShell(), _WriterModel(""), "writer")
    assert attrs["selection.active"] is False


def test_an_unprobed_model_is_visible():
    attrs = _open_attributes(FakeShell(), _WriterModel(), "writer")
    assert attrs["caps.measured"] is False
    assert attrs["caps.agentic"] is False


def test_the_cached_verdict_is_reported():
    shell = FakeShell(config={"llm_base_urls": "http://relay",
                              "llm_default_models": "llama3.2"})
    capabilities.save_cached(
        shell, "http://relay", "llama3.2",
        capabilities.Capabilities(model="llama3.2", accepts_tools=True,
                                  calls_tool=True, chains=True))
    attrs = _open_attributes(shell, _WriterModel(), "writer")
    assert attrs["caps.measured"] is True
    assert attrs["caps.agentic"] is True


def test_a_measured_non_agentic_model_is_distinct_from_an_unprobed_one():
    """C'est LA distinction actionnable : « sonde jamais lancée » se corrige
    par un geste utilisateur, « modèle incapable » par un autre modèle."""
    shell = FakeShell(config={"llm_base_urls": "http://relay",
                              "llm_default_models": "mistral"})
    capabilities.save_cached(
        shell, "http://relay", "mistral",
        capabilities.Capabilities(model="mistral", accepts_tools=True,
                                  calls_tool=False, chains=False))
    attrs = _open_attributes(shell, _WriterModel(), "writer")
    assert attrs["caps.measured"] is True
    assert attrs["caps.agentic"] is False


def test_open_attributes_never_raise():
    attrs = _open_attributes(FakeShell(), _BrokenModel(), "writer")
    assert attrs["selection.active"] is False


def test_calc_has_no_meaningful_text_selection():
    attrs = _open_attributes(FakeShell(), object(), "calc")
    assert attrs["selection.active"] is False
