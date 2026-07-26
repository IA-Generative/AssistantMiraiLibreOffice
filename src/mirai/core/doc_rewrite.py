"""Réécriture du document entier — pilotée par Python, pas par le modèle.

Pourquoi ne pas s'en remettre au tool calling : sur `llama-3.3-70b-instruct`,
une demande comme « réécris l'article en deux paragraphes » sans sélection
donnait invariablement `iterations=2` — le modèle appelait bien l'outil de
LECTURE, recevait la carte du document… puis répondait du texte, sans jamais
appeler l'outil d'écriture. Trois renforts successifs (consigne système, rappel
dans le résultat de l'outil, ligne de portée en tête de la demande) ont amélioré
la situation sans la régler : les modèles de cette taille n'enchaînent pas deux
tool calls de façon fiable.

La parade est celle du plan pour les presets « pipeline » : **le LLM n'est
qu'une fonction texte**, et Python applique le résultat. Aucun tool call n'est
requis, donc plus rien à espérer du modèle — c'est déterministe.

Ce module ne connaît pas UNO : il reçoit des paragraphes, rend des paragraphes.
"""

from __future__ import annotations

import re

# Une demande de modification du document. On reste large : le coût d'un faux
# positif est faible (le modèle réécrit à l'identique), celui d'un faux négatif
# est une action sans effet — ce qu'on cherche justement à éliminer.
_REWRITE_VERBS = (
    "réécri", "reecri", "récri", "recri", "réécrit", "restructur", "restructure",
    "réorganis", "reorganis", "reformul", "réorganise", "condens", "fusionn",
    "découp", "decoup", "divis", "scind", "résum", "resum", "raccourci",
    "allong", "développ", "developp", "corrig", "traduis", "traduit",
    "simplifi", "clarifi", "harmonis", "uniformis", "réviser", "revois",
    "mets à jour", "mets a jour", "transforme", "adapte", "rends",
)

_DOC_WORDS = ("document", "article", "texte", "page", "note", "courrier",
              "rapport", "ensemble", "tout")


def wants_document_rewrite(prompt: str) -> bool:
    """Vrai si la demande vise une réécriture du document.

    Appelée seulement quand rien n'est sélectionné : la portée est alors le
    document entier, et la question est « faut-il l'écrire, ou seulement
    répondre ? ».
    """
    text = (prompt or "").lower()
    if not text.strip():
        return False
    if not any(verb in text for verb in _REWRITE_VERBS):
        return False
    # Une question pure appelle une réponse, pas une modification.
    if text.lstrip().startswith(("qu'", "que ", "quel", "pourquoi", "comment",
                                 "combien", "explique", "résume-moi ce que")):
        return False
    return True


def mentions_whole_document(prompt: str) -> bool:
    """Vrai si la demande nomme explicitement le document dans son ensemble."""
    text = (prompt or "").lower()
    return any(word in text for word in _DOC_WORDS)


def build_rewrite_prompt(paragraphs, instruction: str) -> str:
    """Demande au modèle un texte brut, un paragraphe par ligne.

    Pas de JSON, pas de tool call, pas de marqueurs : le format le plus simple
    qu'un modèle moyen produit de façon fiable.
    """
    numbered = "\n".join(f"[P{index}] {text}"
                         for index, text in enumerate(paragraphs, start=1))
    return (
        "DOCUMENT ACTUEL (un paragraphe par ligne, numérotés) :\n"
        f"{numbered}\n\n"
        f"DEMANDE : {instruction}\n\n"
        "RÈGLES DE RÉPONSE :\n"
        "- Renvoie UNIQUEMENT le document réécrit, rien d'autre.\n"
        "- UN paragraphe par ligne, sans les marqueurs [Pn], sans ligne vide.\n"
        "- Pas d'introduction, pas de commentaire, pas de markdown.\n"
        "- Conserve la langue d'origine.\n"
        "- Si le premier paragraphe est un titre, garde-le comme première ligne."
    )


def parse_rewritten(text: str):
    """Extrait les paragraphes de la réponse du modèle.

    Tolérant : retire les marqueurs [Pn] si le modèle les a conservés, les
    puces, les clôtures de bloc de code, et ignore les lignes vides.
    """
    paragraphs = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("```"):
            continue
        line = re.sub(r"^\[P\d+\]\s*", "", line)
        line = re.sub(r"^[-*•]\s+", "", line)
        if line:
            paragraphs.append(line)
    return paragraphs
