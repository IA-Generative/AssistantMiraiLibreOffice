"""Convert LLM output (Markdown or HTML) into native LibreOffice Writer content.

Entry point: :func:`insert_formatted`. Everything else in this package is an
implementation detail of the Markdown/HTML -> UNO conversion.
"""

from .insert import insert_formatted

__all__ = ["insert_formatted"]
