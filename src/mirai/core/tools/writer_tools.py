"""Tools Writer — lectures de contexte et mutations structurelles courtes.

Invariant de conception : la prose longue générée par le LLM ne transite
JAMAIS en argument JSON — elle arrive par le sink de streaming (voir
orchestrator). Les tools mutants restent donc courts et sûrs.
"""

from ..tool_calls import ToolResult, ToolSpec


def _selection_range(ctx):
    return ctx.controller.getSelection().getByIndex(0)


def get_selection(ctx, args):
    rng = _selection_range(ctx)
    text = rng.getString()
    if not text.strip():
        content = "La sélection est vide (curseur simple, aucun texte sélectionné)."
    else:
        content = f"SÉLECTION ({len(text)} caractères) :\n{text}"
    return ToolResult(
        call_id="", ok=True, content=content,
        data={"text": text, "char_count": len(text), "is_empty": not text.strip()},
    )


def get_document_map(ctx, args):
    max_chars = int(args.get("max_chars", 6000))
    lines = []
    total = 0
    index = 0
    enumeration = ctx.model.Text.createEnumeration()
    truncated = False
    while enumeration.hasMoreElements():
        para = enumeration.nextElement()
        try:
            if not para.supportsService("com.sun.star.text.Paragraph"):
                continue
        except Exception:
            continue
        index += 1
        content = para.getString()
        line = f"[P{index}] {content}" if content.strip() else f"[P{index}] (vide)"
        total += len(line) + 1
        if total > max_chars:
            truncated = True
            break
        lines.append(line)
    body = "\n".join(lines)
    if truncated:
        body += f"\n[... document tronqué à {max_chars} caractères ...]"
    return ToolResult(call_id="", ok=True, content=body or "(document vide)",
                      data={"paragraph_count": index, "truncated": truncated})


def replace_selection(ctx, args):
    text = args["text"]
    rng = _selection_range(ctx)
    previous_length = len(rng.getString())
    rng.setString(text)
    try:
        ctx.controller.select(rng)
    except Exception:
        pass
    return ToolResult(
        call_id="", ok=True,
        content=f"Sélection remplacée ({previous_length} → {len(text)} caractères).",
    )


def insert_text(ctx, args):
    content = args["text"]
    position = args.get("position", "after_selection")
    if position == "end_of_document":
        text_obj = ctx.model.Text
        cursor = text_obj.createTextCursor()
        cursor.gotoEnd(False)
    else:
        rng = _selection_range(ctx)
        text_obj = rng.getText()
        cursor = text_obj.createTextCursorByRange(rng)
        cursor.collapseToEnd()
    text_obj.insertString(cursor, content, False)
    return ToolResult(call_id="", ok=True,
                      content=f"{len(content)} caractères insérés ({position}).")


def find_replace(ctx, args):
    pairs = args["pairs"]
    replace_all = bool(args.get("replace_all", False))
    doc = ctx.model
    applied = 0
    not_found = []
    for pair in pairs:
        find = str(pair.get("find", ""))
        replacement = str(pair.get("replace", ""))
        if not find:
            continue
        descriptor = doc.createSearchDescriptor()
        descriptor.SearchString = find
        try:
            descriptor.SearchCaseSensitive = True
        except Exception:
            pass
        found = doc.findFirst(descriptor)
        if found is None:
            not_found.append(find[:80])
            continue
        while found is not None:
            found.setString(replacement)
            applied += 1
            if not replace_all:
                break
            found = doc.findNext(found.getEnd(), descriptor)
    summary = f"{applied} remplacement(s) effectué(s)."
    if not_found:
        summary += " Introuvable (texte exact requis) : " + " | ".join(not_found)
    return ToolResult(call_id="", ok=True, content=summary,
                      data={"applied": applied, "not_found": not_found})


def register(registry):
    registry.register(ToolSpec(
        name="writer_get_selection",
        description="Lit le texte actuellement sélectionné dans le document Writer.",
        parameters={"type": "object", "properties": {}},
        handler=get_selection, apps=("writer",),
    ))
    registry.register(ToolSpec(
        name="writer_get_document_map",
        description=("Lit le document entier sous forme de paragraphes numérotés "
                     "[P1], [P2]… Utile pour repérer où intervenir."),
        parameters={"type": "object", "properties": {
            "max_chars": {"type": "integer", "default": 6000, "minimum": 500, "maximum": 20000},
        }},
        handler=get_document_map, apps=("writer",),
    ))
    registry.register(ToolSpec(
        name="writer_replace_selection",
        description=("Remplace le texte sélectionné par un texte court. Pour une "
                     "réécriture longue, réponds plutôt en texte final (elle sera "
                     "insérée automatiquement)."),
        parameters={"type": "object", "properties": {
            "text": {"type": "string"},
        }, "required": ["text"]},
        handler=replace_selection, apps=("writer",), mutates=True,
    ))
    registry.register(ToolSpec(
        name="writer_insert_text",
        description="Insère un texte après la sélection ou en fin de document.",
        parameters={"type": "object", "properties": {
            "text": {"type": "string"},
            "position": {"type": "string", "enum": ["after_selection", "end_of_document"],
                         "default": "after_selection"},
        }, "required": ["text"]},
        handler=insert_text, apps=("writer",), mutates=True,
    ))
    registry.register(ToolSpec(
        name="writer_find_replace",
        description=("Remplace des passages exacts du document. Chaque paire "
                     "{find, replace} : 'find' doit reproduire exactement le texte "
                     "du document (copie depuis writer_get_document_map)."),
        parameters={"type": "object", "properties": {
            "pairs": {"type": "array", "items": {"type": "object", "properties": {
                "find": {"type": "string"},
                "replace": {"type": "string"},
            }, "required": ["find", "replace"]}},
            "replace_all": {"type": "boolean", "default": False},
        }, "required": ["pairs"]},
        handler=find_replace, apps=("writer",), mutates=True,
    ))
