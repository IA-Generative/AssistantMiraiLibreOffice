"""La case « Ajouter à la suite » doit piloter TOUTES les destinations.

Elle avait été branchée sur un seul chemin — celui du preset « Modifier » —
et ce preset a ensuite été retiré des chips. La case est alors restée à
l'écran sans plus rien commander : cochée ou non, le résultat était le même.

Le remède est structurel : un helper UNIQUE traduit le choix en destination,
et chaque preset le traverse obligatoirement.
"""

from unittest.mock import MagicMock

from src.mirai.core.presets import text_sink
from src.mirai.core.sinks import WriterInsertSink, WriterReplaceSink


def _ctx():
    return MagicMock()


def test_checked_appends_between_markers():
    sink = text_sink(_ctx(), True, "\n---début---\n", "\n---fin---\n")

    assert isinstance(sink, WriterInsertSink)
    assert sink.header_marker == "\n---début---\n"
    assert sink.footer_marker == "\n---fin---\n"


def test_unchecked_replaces_the_selection():
    sink = text_sink(_ctx(), False, "\n---début---\n", "\n---fin---\n")

    assert isinstance(sink, WriterReplaceSink)


def test_extra_options_survive_in_append_mode():
    """Stop phrases et détection de question ne doivent pas être perdues."""
    sink = text_sink(_ctx(), True, "a", "b",
                     stop_phrases=["stop"], question_patterns=["?"])

    assert sink.stop_phrases == ["stop"]
    assert sink.question_patterns == ["?"]


def test_every_writer_preset_accepts_the_choice():
    """Un preset qui n'accepte pas le paramètre l'ignorerait en silence."""
    import inspect

    from src.mirai.core import presets

    for preset in presets.presets_for("writer"):
        if preset.mode != "pipeline":
            continue
        signature = inspect.signature(preset.runner)
        assert "append_mode" in signature.parameters, (
            f"{preset.id} ne reçoit pas le choix de destination")


def test_defaults_match_historic_behaviour():
    """Sans choix transmis, chaque preset garde son comportement d'origine."""
    import inspect

    from src.mirai.core import presets

    expected = {"summarize": True, "simplify": True,
                "shorten": False, "lengthen": False}
    for preset_id, appends in expected.items():
        runner = presets.get_preset(preset_id).runner
        default = inspect.signature(runner).parameters["append_mode"].default
        assert default is appends, f"{preset_id} : défaut inattendu"
