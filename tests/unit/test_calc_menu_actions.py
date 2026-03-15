"""
Unit tests for src/mirai/menu_actions/calc.py

Run with:
    .venv/bin/pytest tests/unit/test_calc_menu_actions.py -v
"""
import unittest
from unittest.mock import MagicMock, call, patch

from tests.stubs.uno_stubs import install

install()

from src.mirai.menu_actions.calc import (  # noqa: E402
    _ERR_PREFIX,
    _analyze_range,
    _edit_cells,
    _extend_cells,
    _generate_formula,
    _transform_to_column,
    handle_calc_action,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cell(text=""):
    """Stateful fake cell: getString/setString mirror a real cell."""
    cell = MagicMock()
    cell._text = text
    cell.getString.side_effect = lambda: cell._text
    cell.setString.side_effect = lambda v: setattr(cell, "_text", v)
    return cell


def _make_sheet(cells: dict):
    """cells: {(col, row): text}  →  getCellByPosition returns a fake cell."""
    cell_map = {pos: _make_cell(t) for pos, t in cells.items()}
    sheet = MagicMock()
    sheet.getCellByPosition.side_effect = lambda c, r: cell_map.setdefault(
        (c, r), _make_cell()
    )
    return sheet, cell_map


def _make_job(stream_chunks=None):
    """Fake job whose stream_request calls the callback with each chunk."""
    job = MagicMock()
    chunks = stream_chunks or ["hello"]

    def _stream(request, api_type, callback):
        for chunk in chunks:
            callback(chunk)

    job.stream_request.side_effect = _stream
    job.get_config.return_value = ""
    return job


# ---------------------------------------------------------------------------
# _extend_cells
# ---------------------------------------------------------------------------

class TestExtendCells(unittest.TestCase):

    def test_appends_chunk_to_non_empty_cell(self):
        sheet, cells = _make_sheet({(0, 0): "foo"})
        job = _make_job(["bar"])
        _extend_cells(job, sheet, range(0, 1), range(0, 1))
        self.assertEqual(cells[(0, 0)].getString(), "foobar")

    def test_skips_empty_cell(self):
        sheet, _ = _make_sheet({(0, 0): ""})
        job = _make_job(["bar"])
        _extend_cells(job, sheet, range(0, 1), range(0, 1))
        job.make_api_request.assert_not_called()

    def test_error_appends_message(self):
        sheet, cells = _make_sheet({(0, 0): "x"})
        job = _make_job()
        job.make_api_request.side_effect = RuntimeError("boom")
        _extend_cells(job, sheet, range(0, 1), range(0, 1))
        self.assertIn("boom", cells[(0, 0)].getString())


# ---------------------------------------------------------------------------
# _edit_cells
# ---------------------------------------------------------------------------

class TestEditCells(unittest.TestCase):

    def test_replaces_cell_content_with_llm_result(self):
        sheet, cells = _make_sheet({(0, 0): "original"})
        job = _make_job(["edited"])
        _edit_cells(job, sheet, range(0, 1), range(0, 1), "make it shorter")
        self.assertEqual(cells[(0, 0)].getString(), "edited")

    def test_error_appended_to_cell(self):
        sheet, cells = _make_sheet({(0, 0): "text"})
        job = _make_job()
        job.make_api_request.side_effect = ValueError("fail")
        _edit_cells(job, sheet, range(0, 1), range(0, 1), "edit")
        self.assertIn("fail", cells[(0, 0)].getString())


# ---------------------------------------------------------------------------
# _transform_to_column
# ---------------------------------------------------------------------------

class TestTransformToColumn(unittest.TestCase):

    def test_writes_to_adjacent_column(self):
        sheet, cells = _make_sheet({(0, 0): "Paris", (0, 1): "Lyon"})
        job = _make_job(["France"])
        _transform_to_column(job, sheet, range(0, 1), range(0, 2), "pays")
        # Results land in col=1 (range(0,1).stop == 1)
        self.assertEqual(cells[(1, 0)].getString(), "France")
        self.assertEqual(cells[(1, 1)].getString(), "France")

    def test_skips_empty_rows(self):
        sheet, cells = _make_sheet({(0, 0): "", (0, 1): "Lyon"})
        job = _make_job(["France"])
        _transform_to_column(job, sheet, range(0, 1), range(0, 2), "pays")
        # row 0 is empty → skipped entirely (output cell never written)
        self.assertNotIn((1, 0), cells)
        self.assertEqual(cells[(1, 1)].getString(), "France")
        self.assertEqual(job.make_api_request.call_count, 1)

    def test_joins_multi_column_source_with_pipe(self):
        sheet, _ = _make_sheet({(0, 0): "A", (1, 0): "B"})
        job = _make_job(["result"])
        _transform_to_column(job, sheet, range(0, 2), range(0, 1), "combine")
        prompt_arg = job.make_api_request.call_args[0][0]
        self.assertIn("A | B", prompt_arg)

    def test_error_writes_err_prefix(self):
        sheet, cells = _make_sheet({(0, 0): "data"})
        job = _make_job()
        job.make_api_request.side_effect = RuntimeError("oops")
        _transform_to_column(job, sheet, range(0, 1), range(0, 1), "transform")
        self.assertTrue(cells[(1, 0)].getString().startswith(_ERR_PREFIX))

    def test_output_column_is_end_col_plus_one(self):
        """With a 3-column selection (0-2), output goes to col 3."""
        sheet, cells = _make_sheet({(0, 0): "x", (1, 0): "y", (2, 0): "z"})
        job = _make_job(["ok"])
        _transform_to_column(job, sheet, range(0, 3), range(0, 1), "test")
        self.assertEqual(cells[(3, 0)].getString(), "ok")


# ---------------------------------------------------------------------------
# _generate_formula
# ---------------------------------------------------------------------------

class TestGenerateFormula(unittest.TestCase):

    def test_writes_formula_to_target_cell(self):
        target = _make_cell()
        job = _make_job(["=SUM(A1:A10)"])
        _generate_formula(job, target, "somme de A1 à A10")
        target.setFormula.assert_called_once_with("=SUM(A1:A10)")

    def test_prepends_equals_if_missing(self):
        target = _make_cell()
        job = _make_job(["SUM(A1:A10)"])  # LLM forgot the =
        _generate_formula(job, target, "somme")
        target.setFormula.assert_called_once_with("=SUM(A1:A10)")

    def test_collects_all_chunks_before_writing(self):
        """Partial chunks must be joined; setFormula called exactly once."""
        target = _make_cell()
        job = _make_job(["=SUM", "(A1", ":A10)"])
        _generate_formula(job, target, "somme")
        target.setFormula.assert_called_once_with("=SUM(A1:A10)")

    def test_fallback_to_setstring_on_setformula_error(self):
        target = _make_cell()
        target.setFormula.side_effect = Exception("invalid formula")
        job = _make_job(["=INVALID("])
        _generate_formula(job, target, "test")
        target.setString.assert_called()

    def test_error_writes_err_prefix(self):
        target = _make_cell()
        job = _make_job()
        job.make_api_request.side_effect = RuntimeError("network error")
        _generate_formula(job, target, "formula")
        target.setString.assert_called_once()
        self.assertTrue(target.setString.call_args[0][0].startswith(_ERR_PREFIX))

    def test_empty_llm_response_does_not_call_setformula(self):
        target = _make_cell()
        job = _make_job(["   "])  # only whitespace
        _generate_formula(job, target, "test")
        target.setFormula.assert_not_called()
        target.setString.assert_not_called()


# ---------------------------------------------------------------------------
# _analyze_range
# ---------------------------------------------------------------------------

class TestAnalyzeRange(unittest.TestCase):

    def _populate_sheet(self, data):
        """data: list of list of str, row-major."""
        cells = {}
        for r, row in enumerate(data):
            for c, val in enumerate(row):
                cells[(c, r)] = val
        return _make_sheet(cells)

    def test_writes_analysis_below_selection(self):
        sheet, cells = self._populate_sheet([["100", "200"], ["300", "400"]])
        job = _make_job(["tendance positive"])
        _analyze_range(job, sheet, range(0, 2), range(0, 2))
        # output row = row_range.stop + 1 = 2 + 1 = 3
        self.assertEqual(cells[(0, 3)].getString(), "tendance positive")

    def test_table_serialized_in_prompt(self):
        sheet, _ = self._populate_sheet([["A", "B"], ["C", "D"]])
        job = _make_job(["ok"])
        _analyze_range(job, sheet, range(0, 2), range(0, 2))
        prompt = job.make_api_request.call_args[0][0]
        self.assertIn("A | B", prompt)
        self.assertIn("C | D", prompt)

    def test_empty_range_skips_llm_call(self):
        sheet, _ = self._populate_sheet([[""]])
        job = _make_job(["analysis"])
        _analyze_range(job, sheet, range(0, 1), range(0, 1))
        job.make_api_request.assert_not_called()

    def test_merge_attempted_on_multi_column(self):
        sheet, _ = self._populate_sheet([["x", "y", "z"]])
        job = _make_job(["ok"])
        mock_range = MagicMock()
        sheet.getCellRangeByPosition.return_value = mock_range
        _analyze_range(job, sheet, range(0, 3), range(0, 1))
        mock_range.merge.assert_called_once_with(True)

    def test_no_merge_on_single_column(self):
        sheet, _ = self._populate_sheet([["x"]])
        job = _make_job(["ok"])
        _analyze_range(job, sheet, range(0, 1), range(0, 1))
        sheet.getCellRangeByPosition.assert_not_called()

    def test_error_writes_err_prefix(self):
        sheet, cells = self._populate_sheet([["data", "more"]])
        job = _make_job()
        job.make_api_request.side_effect = RuntimeError("timeout")
        _analyze_range(job, sheet, range(0, 2), range(0, 1))
        out_cell = cells[(0, 2)]
        self.assertTrue(out_cell.getString().startswith(_ERR_PREFIX))


# ---------------------------------------------------------------------------
# handle_calc_action — routing
# ---------------------------------------------------------------------------

class TestHandleCalcAction(unittest.TestCase):

    def _make_model(self, start_col=0, end_col=1, start_row=0, end_row=2):
        area = MagicMock()
        area.StartColumn = start_col
        area.EndColumn = end_col
        area.StartRow = start_row
        area.EndRow = end_row

        selection = MagicMock()
        selection.getRangeAddress.return_value = area

        sheet = MagicMock()
        sheet.getCellByPosition.return_value = _make_cell("content")

        model = MagicMock(spec=["Sheets", "CurrentController"])
        model.CurrentController.ActiveSheet = sheet
        model.CurrentController.Selection = selection
        return model, sheet, selection

    def test_non_sheets_model_returns_false(self):
        job = _make_job()
        model = MagicMock(spec=[])  # no Sheets attribute
        self.assertFalse(handle_calc_action(job, "ExtendSelection", model))

    def test_settings_opens_dialog_and_returns_true(self):
        job = _make_job()
        model, *_ = self._make_model()
        result = handle_calc_action(job, "settings", model)
        self.assertTrue(result)
        job.settings_box.assert_called_once()

    def test_extend_selection_calls_extend_cells(self):
        job = _make_job(["ext"])
        model, sheet, _ = self._make_model(start_col=0, end_col=0, start_row=0, end_row=0)
        sheet.getCellByPosition.return_value = _make_cell("seed")
        handle_calc_action(job, "ExtendSelection", model)
        job.stream_request.assert_called()

    def test_edit_selection_calls_edit_cells(self):
        job = _make_job(["edited"])
        job.input_box.return_value = "make it shorter"
        model, sheet, _ = self._make_model(start_col=0, end_col=0, start_row=0, end_row=0)
        sheet.getCellByPosition.return_value = _make_cell("original")
        handle_calc_action(job, "EditSelection", model)
        job.input_box.assert_called_once()
        job.stream_request.assert_called()

    def test_transform_to_column_empty_input_does_nothing(self):
        job = _make_job(["result"])
        job.input_box.return_value = ""  # user cancelled
        model, *_ = self._make_model()
        handle_calc_action(job, "TransformToColumn", model)
        job.make_api_request.assert_not_called()

    def test_transform_to_column_with_input_calls_llm(self):
        job = _make_job(["FR"])
        job.input_box.return_value = "pays"
        model, sheet, _ = self._make_model(start_col=0, end_col=0, start_row=0, end_row=0)
        sheet.getCellByPosition.return_value = _make_cell("Paris")
        handle_calc_action(job, "TransformToColumn", model)
        job.make_api_request.assert_called()

    def test_generate_formula_empty_input_does_nothing(self):
        job = _make_job(["=SUM(A1)"])
        job.input_box.return_value = ""
        model, *_ = self._make_model()
        handle_calc_action(job, "GenerateFormula", model)
        job.make_api_request.assert_not_called()

    def test_generate_formula_with_input_writes_formula(self):
        target = _make_cell()
        job = _make_job(["=SUM(A1:A10)"])
        job.input_box.return_value = "somme de A1 à A10"
        model, sheet, _ = self._make_model()
        sheet.getCellByPosition.return_value = target
        handle_calc_action(job, "GenerateFormula", model)
        target.setFormula.assert_called_once_with("=SUM(A1:A10)")

    def test_analyze_range_triggers_llm(self):
        job = _make_job(["analyse"])
        model, sheet, _ = self._make_model(start_col=0, end_col=1, start_row=0, end_row=1)
        cells = {}
        def get_cell(c, r):
            return cells.setdefault((c, r), _make_cell("val"))
        sheet.getCellByPosition.side_effect = get_cell
        handle_calc_action(job, "AnalyzeRange", model)
        job.make_api_request.assert_called()

    def test_always_returns_true_for_known_args(self):
        for arg in ("ExtendSelection", "EditSelection", "TransformToColumn",
                    "AnalyzeRange", "GenerateFormula", "settings"):
            job = _make_job()
            job.input_box.return_value = "x"
            model, sheet, _ = self._make_model()
            sheet.getCellByPosition.return_value = _make_cell("v")
            result = handle_calc_action(job, arg, model)
            self.assertTrue(result, msg=f"Expected True for arg={arg!r}")


if __name__ == "__main__":
    unittest.main()
