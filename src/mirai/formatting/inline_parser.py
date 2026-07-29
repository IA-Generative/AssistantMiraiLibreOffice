"""Inline Markdown parsing: bold, italic, code spans and links.

Each marker style has its own small, single-purpose regex (no shared
backreference numbering across a giant alternation) so the priority rules
stay easy to read: at every position we take whichever pattern matches
earliest, and ties are broken by list order (more specific markers first).
"""

import re

from .ast_nodes import Bold, Code, Italic, Link, Text

_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD_ITALIC_STAR = re.compile(r"\*\*\*(.+?)\*\*\*")
_BOLD_ITALIC_US = re.compile(r"(?<!\w)___(.+?)___(?!\w)")
_BOLD_STAR = re.compile(r"\*\*(.+?)\*\*")
_BOLD_US = re.compile(r"(?<!\w)__(.+?)__(?!\w)")
_ITALIC_STAR = re.compile(r"\*(.+?)\*")
_ITALIC_US = re.compile(r"(?<!\w)_(.+?)_(?!\w)")

# Ordered by priority: longer/more specific markers must win ties on the
# same start position (e.g. "**x**" must not be read as italic "*" + "*").
_PATTERNS = [
    ("code", _CODE),
    ("link", _LINK),
    ("bold_italic", _BOLD_ITALIC_STAR),
    ("bold_italic", _BOLD_ITALIC_US),
    ("bold", _BOLD_STAR),
    ("bold", _BOLD_US),
    ("italic", _ITALIC_STAR),
    ("italic", _ITALIC_US),
]


def parse_inline(text):
    """Parse one line of inline Markdown into a list of AST inline nodes."""
    nodes = []
    pos = 0
    n = len(text)
    while pos < n:
        best_start = None
        best_kind = None
        best_match = None
        for kind, pattern in _PATTERNS:
            m = pattern.search(text, pos)
            if m and (best_start is None or m.start() < best_start):
                best_start, best_kind, best_match = m.start(), kind, m
        if best_match is None:
            nodes.append(Text(text[pos:]))
            break
        if best_match.start() > pos:
            nodes.append(Text(text[pos:best_match.start()]))
        nodes.append(_build_node(best_kind, best_match))
        pos = best_match.end()
    return nodes


def _build_node(kind, match):
    if kind == "code":
        return Code(match.group(1))
    if kind == "link":
        return Link(parse_inline(match.group(1)), match.group(2))
    if kind == "bold_italic":
        return Bold([Italic(parse_inline(match.group(1)))])
    if kind == "bold":
        return Bold(parse_inline(match.group(1)))
    return Italic(parse_inline(match.group(1)))
