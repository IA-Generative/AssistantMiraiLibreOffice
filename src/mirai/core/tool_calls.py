"""Représentation interne des outils et de leurs appels (miroir MCP).

ToolSpec/ToolCall/ToolResult sont l'unique format interne, quel que soit le
format de fil (tool calling OpenAI natif ou repli JSON). Le validateur couvre
un SOUS-ENSEMBLE documenté de JSON Schema (stdlib uniquement, pas de pip) :
type, properties, required, items, enum, default, maxLength, minimum, maximum.
Coercitions volontaires ("3" → 3, "true" → True, 50000 → 20000 sous un plafond
de 20000) : les petits modèles émettent souvent des scalaires sous forme de
chaînes, et demandent des tailles de lecture « au maximum ». Un dépassement de
borne se rattrape ; il ne justifie pas de leur faire perdre un tour.
"""

import dataclasses
import math


@dataclasses.dataclass
class ToolSpec:
    name: str                  # snake_case, préfixé writer_/calc_/ui_
    description: str           # français, 1-2 phrases, destiné au LLM
    parameters: dict           # JSON Schema (sous-ensemble supporté)
    handler: object            # Callable[[ToolContext, dict], ToolResult]
    apps: tuple = ("writer", "calc")
    mutates: bool = False      # True → ouvre le contexte undo du run


@dataclasses.dataclass
class ToolCall:
    id: str                    # id fourni par l'API, ou "call_<n>" en mode JSON
    name: str
    arguments: dict
    raw: str = ""              # JSON brut reçu (debug local, jamais télémétré)


@dataclasses.dataclass
class ToolResult:
    call_id: str
    ok: bool
    content: str               # texte renvoyé au LLM (plafonné par le registre)
    data: dict = None          # payload structuré pour l'UI
    error: str = ""


def _coerce(expected_type, value):
    """Retourne (ok, valeur_coercée)."""
    if expected_type == "string":
        if isinstance(value, str):
            return True, value
        if isinstance(value, (int, float, bool)):
            return True, str(value)
        return False, value
    if expected_type == "integer":
        if isinstance(value, bool):
            return False, value
        if isinstance(value, int):
            return True, value
        if isinstance(value, float) and value.is_integer():
            return True, int(value)
        if isinstance(value, str):
            try:
                return True, int(value.strip())
            except ValueError:
                return False, value
        return False, value
    if expected_type == "number":
        if isinstance(value, bool):
            return False, value
        if isinstance(value, (int, float)):
            return True, value
        if isinstance(value, str):
            try:
                return True, float(value.strip())
            except ValueError:
                return False, value
        return False, value
    if expected_type == "boolean":
        if isinstance(value, bool):
            return True, value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in ("true", "vrai", "1", "yes", "oui"):
                return True, True
            if lowered in ("false", "faux", "0", "no", "non"):
                return True, False
        return False, value
    if expected_type == "array":
        return isinstance(value, list), value
    if expected_type == "object":
        return isinstance(value, dict), value
    return True, value  # type inconnu/absent : laisser passer


def _validate_value(schema, value, path):
    """Valide/coerce une valeur contre un sous-schéma. Retourne (ok, err, val)."""
    expected_type = schema.get("type")
    if expected_type:
        ok, value = _coerce(expected_type, value)
        if not ok:
            return False, f"paramètre '{path}' : type attendu {expected_type}", value

    enum = schema.get("enum")
    if enum is not None and value not in enum:
        return False, f"paramètre '{path}' : valeur attendue parmi {enum}", value

    if expected_type == "string":
        max_length = schema.get("maxLength")
        if max_length is not None and len(value) > int(max_length):
            value = value[: int(max_length)]
    if expected_type in ("integer", "number"):
        # RAMENER dans les bornes plutôt que rejeter. Ces bornes protègent
        # l'appel (taille de lecture, plafonds), elles n'expriment pas une
        # exigence métier : un modèle qui demande 50 000 caractères veut « le
        # plus possible », pas échouer. Rejeter lui faisait perdre un tour —
        # et souvent abandonner. Même traitement que `maxLength`, qui tronque
        # déjà les chaînes trop longues au lieu de les refuser.
        # Arrondir vers l'INTÉRIEUR : ceil pour un plancher, floor pour un
        # plafond. Un simple int(borne) retomberait hors bornes dès que la
        # borne est fractionnaire (int(0.5) == 0, sous un minimum de 0.5).
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and value < minimum:
            value = math.ceil(minimum) if expected_type == "integer" else minimum
        if maximum is not None and value > maximum:
            value = math.floor(maximum) if expected_type == "integer" else maximum
    if expected_type == "array":
        item_schema = schema.get("items")
        if item_schema:
            coerced_items = []
            for i, item in enumerate(value):
                ok, err, item = _validate_value(item_schema, item, f"{path}[{i}]")
                if not ok:
                    return False, err, value
                coerced_items.append(item)
            value = coerced_items
    if expected_type == "object":
        props = schema.get("properties")
        if props:
            ok, err, value = _validate_object(schema, value, path + ".")
            if not ok:
                return False, err, value

    return True, "", value


def _validate_object(schema, args, prefix=""):
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    coerced = dict(args)

    for name in required:
        if name not in coerced:
            return False, f"paramètre requis manquant : '{prefix}{name}'", coerced

    for name, sub_schema in properties.items():
        if name not in coerced:
            if "default" in sub_schema:
                coerced[name] = sub_schema["default"]
            continue
        ok, err, value = _validate_value(sub_schema, coerced[name], prefix + name)
        if not ok:
            return False, err, coerced
        coerced[name] = value

    return True, "", coerced


def validate_args(schema, args):
    """Valide `args` contre `schema`. Retourne (ok, message_erreur, args_coercés).

    Les clés inconnues sont conservées (tolérance aux modèles verbeux) ;
    seules les clés déclarées sont validées/coercées.
    """
    if not isinstance(args, dict):
        return False, "les arguments doivent être un objet JSON", {}
    if not isinstance(schema, dict) or not schema:
        return True, "", dict(args)
    return _validate_object(schema, args)
