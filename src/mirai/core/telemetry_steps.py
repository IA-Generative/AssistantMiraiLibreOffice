"""Trace fonctionnelle : ce que l'assistant a FAIT, sans jamais ce qu'il a lu.

Le journal d'actions (onglet « Actions ») est écrit pour l'utilisateur, en
français, et cite volontiers le document — « Titre conservé : « Rapport
annuel 2026 » ». Ces lignes vont dans `~/log.txt`, qui ne quitte pas le poste.

La télémétrie, elle, **part sur le réseau**. Le vocabulaire ci-dessous et le
filtre d'attributs existent pour qu'aucune phrase du document ne puisse s'y
glisser — aujourd'hui par un appel distrait, demain par un appelant qui n'aura
pas lu ce module. Le filtre ne fait pas confiance à l'appelant : il n'accepte
QUE des nombres, des booléens et des étiquettes prises dans un vocabulaire
fermé. Toute chaîne libre est écartée, silencieusement et par construction.
"""

import re

SPAN = "AssistantStep"

# Étapes fonctionnelles — noms stables, agrégeables côté observabilité.
# Ajouter une étape = ajouter une constante ici, jamais une chaîne libre.
PRESET_START = "preset.start"
PRESET_DONE = "preset.done"
SELECTION_START = "selection.rewrite.start"
SELECTION_DONE = "selection.rewrite.done"
DOCUMENT_READ = "document.read"
DOCUMENT_START = "document.rewrite.start"
DOCUMENT_DONE = "document.rewrite.done"
DOCUMENT_EMPTY = "document.rewrite.empty"
REASONING_STARVED = "llm.reasoning_starved"

STEPS = frozenset({
    PRESET_START, PRESET_DONE, SELECTION_START, SELECTION_DONE,
    DOCUMENT_READ, DOCUMENT_START, DOCUMENT_DONE, DOCUMENT_EMPTY,
    REASONING_STARVED,
})

# Une étiquette : minuscules, chiffres, point/tiret/souligné. Assez pour un
# nom de preset ou un statut, trop étroit pour une phrase.
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")


def safe_attributes(raw):
    """Ne garde que ce qui ne peut pas porter de contenu documentaire.

    Nombres et booléens passent tels quels. Les chaînes ne passent que si elles
    ressemblent à une étiquette (`_LABEL_RE`) : « resume », « ok », « length ».
    Une phrase, un extrait de paragraphe ou un titre échouent au motif — espaces,
    majuscules, ponctuation — et sont écartés.
    """
    clean = {}
    for key, value in (raw or {}).items():
        if not isinstance(key, str) or not _LABEL_RE.match(key):
            continue
        if isinstance(value, bool) or isinstance(value, (int, float)):
            clean[key] = value
        elif isinstance(value, str) and _LABEL_RE.match(value):
            clean[key] = value
    return clean


def emit(shell, step, attributes=None):
    """Émet une étape fonctionnelle. Ne lève jamais : une trace n'est pas le travail."""
    if step not in STEPS:
        return False
    payload = safe_attributes(attributes)
    payload["step.name"] = step
    try:
        shell.telemetry(SPAN, payload)
    except Exception:
        return False
    return True
