"""Unit tests for the AST -> UNO writer, using plain MagicMock text/cursor
objects (no LibreOffice runtime needed) — same harness style as
test_summarize_writer.py.
"""

import unittest
from unittest.mock import MagicMock

from src.mirai.formatting.insert import insert_formatted


def _make_harness():
    inserted = []
    props = {}

    cursor = MagicMock()
    cursor.getPropertyValue.side_effect = lambda name: props.get(name, "")
    cursor.setPropertyValue.side_effect = lambda name, value: props.__setitem__(name, value)

    text_obj = MagicMock()
    text_obj.insertString.side_effect = lambda cur, s, absorb: inserted.append(("text", s, dict(props)))
    text_obj.insertControlCharacter.side_effect = lambda cur, kind, absorb: inserted.append(("ctrl", kind))

    model = MagicMock()
    return model, text_obj, cursor, inserted


class TestPlainTextFallback(unittest.TestCase):
    def test_plain_prose_inserted_as_one_run_with_standard_style(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "Un texte simple.")

        text_calls = [c for c in inserted if c[0] == "text"]
        self.assertEqual(len(text_calls), 1)
        self.assertEqual(text_calls[0][1], "Un texte simple.")
        self.assertEqual(cursor.setPropertyValue.call_args_list[0].args, ("ParaStyleName", "Standard"))


class TestHeadingAndEmphasis(unittest.TestCase):
    def test_heading_gets_heading_style(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "# Titre")

        para_style_calls = [
            c.args for c in cursor.setPropertyValue.call_args_list if c.args[0] == "ParaStyleName"
        ]
        self.assertIn(("ParaStyleName", "Heading 1"), para_style_calls)

    def test_bold_sets_char_weight_before_insert(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "du **gras**")

        text_calls = [c for c in inserted if c[0] == "text"]
        bold_run = next(c for c in text_calls if c[1] == "gras")
        self.assertEqual(bold_run[2]["CharWeight"], 150.0)

    def test_markdown_markers_never_reach_the_document(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "# Titre\n\ndu **gras** et *italique*, et un [lien](https://x.test)")

        full_text = "".join(c[1] for c in inserted if c[0] == "text")
        for marker in ("#", "**", "](", "https://x.test)"):
            self.assertNotIn(marker, full_text)


class TestLists(unittest.TestCase):
    def test_bullet_list_uses_list_bullet_style(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "- un\n- deux")

        para_style_calls = [
            c.args for c in cursor.setPropertyValue.call_args_list if c.args[0] == "ParaStyleName"
        ]
        self.assertTrue(all(call == ("ParaStyleName", "List Bullet") for call in para_style_calls[:2]))


class TestLinks(unittest.TestCase):
    def test_link_sets_hyperlink_url(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "[le site](https://example.com)")

        text_calls = [c for c in inserted if c[0] == "text"]
        link_run = next(c for c in text_calls if c[1] == "le site")
        self.assertEqual(link_run[2]["HyperLinkURL"], "https://example.com")


class TestEmptyInput(unittest.TestCase):
    def test_empty_string_inserts_nothing(self):
        model, text_obj, cursor, inserted = _make_harness()
        insert_formatted(model, text_obj, cursor, "")
        self.assertEqual(inserted, [])


if __name__ == "__main__":
    unittest.main()
