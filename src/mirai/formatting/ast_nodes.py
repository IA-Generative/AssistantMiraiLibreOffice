"""Small, format-agnostic AST shared by the Markdown and HTML parsers.

Both parsers produce the same node types so the UNO writer only has to know
how to render this AST once, regardless of what the LLM actually returned.
"""

from collections import namedtuple

# Block-level nodes
Heading = namedtuple("Heading", ["level", "inlines", "align"])
Paragraph = namedtuple("Paragraph", ["lines", "align"])  # lines: list[list[inline]]
ListItem = namedtuple("ListItem", ["ordered", "level", "inlines"])
Blockquote = namedtuple("Blockquote", ["inlines"])
CodeBlock = namedtuple("CodeBlock", ["text"])
Table = namedtuple("Table", ["header", "rows"])  # header/rows: list[list[inline]]

# Inline nodes
Text = namedtuple("Text", ["value"])
Bold = namedtuple("Bold", ["children"])
Italic = namedtuple("Italic", ["children"])
Code = namedtuple("Code", ["value"])
Link = namedtuple("Link", ["children", "url"])
