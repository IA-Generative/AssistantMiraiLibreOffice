"""Trace fonctionnelle : agrégeable côté observabilité, muette sur le document.

Le journal d'actions cite le document (« ↳ Titre conservé : « Rapport annuel
2026 » »). Il part dans l'onglet Actions et dans `~/log.txt`, qui restent sur le
poste. La télémétrie, elle, QUITTE la machine : le filtre ci-dessous est ce qui
garantit qu'aucune phrase du document ne l'accompagne — y compris le jour où un
appelant transmettra une chaîne libre sans avoir lu le module.
"""

from src.mirai.core import telemetry_steps


class FakeShell:
    def __init__(self):
        self.spans = []

    def telemetry(self, name, attributes=None):
        self.spans.append((name, attributes or {}))


# ── Ce qui ne doit JAMAIS partir ────────────────────────────────────────

def test_document_content_never_reaches_telemetry():
    """Le cas réel : un titre de document passé par mégarde en attribut."""
    dirty = {
        "document.title": "Rapport annuel 2026 — synthèse",
        "paragraph": "Le chat dort sur le canapé toute la journée.",
        "prompt": "réduis à deux paragraphes",
        "user.email": "prenom.nom@interieur.gouv.fr",
    }
    assert telemetry_steps.safe_attributes(dirty) == {}


def test_numbers_and_flags_pass_through():
    kept = telemetry_steps.safe_attributes({
        "document.paragraphs": 45,
        "result.paragraphs": 2,
        "append.mode": True,
        "ratio": 0.5,
    })
    assert kept == {"document.paragraphs": 45, "result.paragraphs": 2,
                    "append.mode": True, "ratio": 0.5}


def test_short_labels_pass_but_sentences_do_not():
    kept = telemetry_steps.safe_attributes({
        "preset.name": "resume",          # étiquette : passe
        "finish.reason": "length",        # étiquette : passe
        "message": "Résumé du document",  # majuscules + espaces : écarté
        "note": "ok mais avec espaces",   # espaces : écarté
    })
    assert kept == {"preset.name": "resume", "finish.reason": "length"}


def test_a_long_slug_is_refused():
    """Une chaîne longue est suspecte, même sans espace : on refuse."""
    assert telemetry_steps.safe_attributes({"k": "a" * 41}) == {}
    assert telemetry_steps.safe_attributes({"k": "a" * 40}) == {"k": "a" * 40}


def test_a_hostile_key_is_refused():
    assert telemetry_steps.safe_attributes({"Contenu du document": 3}) == {}


# ── Ce qui doit partir ──────────────────────────────────────────────────

def test_a_known_step_is_emitted_with_its_name():
    shell = FakeShell()
    ok = telemetry_steps.emit(shell, telemetry_steps.DOCUMENT_DONE,
                              {"body.paragraphs": 45, "result.paragraphs": 2})
    assert ok
    name, attrs = shell.spans[0]
    assert name == telemetry_steps.SPAN
    assert attrs["step.name"] == "document.rewrite.done"
    assert attrs["body.paragraphs"] == 45


def test_an_unknown_step_is_never_emitted():
    """Le vocabulaire est fermé : pas de nom d'étape inventé au fil de l'eau."""
    shell = FakeShell()
    assert telemetry_steps.emit(shell, "document.something.new") is False
    assert shell.spans == []


def test_every_declared_step_is_accepted():
    shell = FakeShell()
    for step in telemetry_steps.STEPS:
        assert telemetry_steps.emit(shell, step), step
    assert len(shell.spans) == len(telemetry_steps.STEPS)


def test_a_broken_telemetry_never_breaks_the_run():
    class Broken:
        def telemetry(self, *_a, **_k):
            raise OSError("réseau coupé")

    assert telemetry_steps.emit(Broken(), telemetry_steps.DOCUMENT_READ) is False
