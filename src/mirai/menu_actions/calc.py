"""Calc menu actions extracted from MainJob.trigger."""

from .shared import apply_settings_result

_ERR_PREFIX = "#ERREUR: "


def _open_settings(job):
    try:
        result = job.settings_box("Settings")
        apply_settings_result(job, result)
    except Exception:
        pass


def _extend_cells(job, sheet, col_range, row_range):
    api_type = str(job.get_config("api_type", "completions")).lower()
    extend_system_prompt = job.get_config("extend_selection_system_prompt", "")
    extend_max_tokens = job.get_config("extend_selection_max_tokens", 70)

    for row in row_range:
        for col in col_range:
            cell = sheet.getCellByPosition(col, row)
            cell_text = cell.getString()
            if not cell_text:
                continue
            try:
                request = job.make_api_request(
                    cell_text,
                    extend_system_prompt,
                    extend_max_tokens,
                    api_type=api_type,
                )

                def append_cell_text(chunk_text, target_cell=cell):
                    target_cell.setString(target_cell.getString() + chunk_text)

                job.stream_request(request, api_type, append_cell_text)
            except Exception as e:
                cell.setString(cell.getString() + ": " + str(e))


def _edit_cells(job, sheet, col_range, row_range, user_input):
    api_type = str(job.get_config("api_type", "completions")).lower()
    edit_system_prompt = job.get_config("edit_selection_system_prompt", "")
    edit_max_new_tokens = job.get_config("edit_selection_max_new_tokens", 0)
    try:
        edit_max_new_tokens = int(edit_max_new_tokens)
    except (TypeError, ValueError):
        edit_max_new_tokens = 0

    for row in row_range:
        for col in col_range:
            cell = sheet.getCellByPosition(col, row)
            try:
                prompt = (
                    "ORIGINAL VERSION:\n"
                    + cell.getString()
                    + "\n Below is an edited version according to the following instructions. "
                    + "Don't waste time thinking, be as fast as you can. "
                    + "The edited text will be a shorter or longer version of the original text "
                    + "based on the instructions. There are no comments in the edited version. "
                    + "The edited version is followed by the end of the document. "
                    + "The original version will be edited as follows to create the edited version:\n"
                    + user_input
                    + "\nEDITED VERSION:\n"
                )

                max_tokens = len(cell.getString()) + edit_max_new_tokens
                request = job.make_api_request(prompt, edit_system_prompt, max_tokens, api_type=api_type)
                cell.setString("")

                def append_edit_text(chunk_text, target_cell=cell):
                    target_cell.setString(target_cell.getString() + chunk_text)

                job.stream_request(request, api_type, append_edit_text)
            except Exception as e:
                cell.setString(cell.getString() + ": " + str(e))


def _transform_to_column(job, sheet, col_range, row_range, user_input):
    """Transform source cells → adjacent output column (non-destructive).

    For each row, joins all selected cells with ' | ', sends to LLM with
    the user instruction, writes the result to the column immediately to
    the right of the selection.
    """
    api_type = str(job.get_config("api_type", "completions")).lower()
    system_prompt = (
        "Tu es un assistant de transformation de données. "
        "Pour chaque valeur fournie, applique l'instruction demandée. "
        "Réponds UNIQUEMENT avec le résultat transformé, sans explication ni ponctuation autour."
    )
    out_col = col_range.stop  # column immediately to the right of the selection

    for row in row_range:
        parts = [sheet.getCellByPosition(col, row).getString() for col in col_range]
        source_text = " | ".join(p for p in parts if p)
        if not source_text:
            continue

        target_cell = sheet.getCellByPosition(out_col, row)
        target_cell.setString("")
        prompt = (
            "VALEUR SOURCE :\n" + source_text
            + "\n\nINSTRUCTION : " + user_input
            + "\n\nRÉSULTAT :"
        )
        try:
            request = job.make_api_request(prompt, system_prompt, 300, api_type=api_type)

            def append_result(chunk_text, tc=target_cell):
                tc.setString(tc.getString() + chunk_text)

            job.stream_request(request, api_type, append_result)
        except Exception as e:
            target_cell.setString(_ERR_PREFIX + str(e))


def _generate_formula(job, target_cell, user_input):
    """Generate a Calc formula from a natural-language description.

    Collects the full streamed response before writing, since a partial
    formula is not valid and must not be committed to the cell mid-stream.
    """
    api_type = str(job.get_config("api_type", "completions")).lower()
    system_prompt = (
        "Tu es un expert LibreOffice Calc. "
        "Tu génères uniquement des formules Calc valides. "
        "Tu réponds UNIQUEMENT avec la formule commençant par =, sans explication ni texte autour."
    )
    prompt = "Génère une formule LibreOffice Calc pour : " + user_input + "\n\nFORMULE :"
    try:
        result_parts = []

        def collect(chunk_text):
            result_parts.append(chunk_text)

        request = job.make_api_request(prompt, system_prompt, 200, api_type=api_type)
        job.stream_request(request, api_type, collect)

        formula = "".join(result_parts).strip()
        if formula:
            if not formula.startswith("="):
                formula = "=" + formula
            try:
                target_cell.setFormula(formula)
            except Exception:
                target_cell.setString(formula)
    except Exception as e:
        target_cell.setString(_ERR_PREFIX + str(e))


def _analyze_range(job, sheet, col_range, row_range):
    """Serialize the selected range as a pipe-delimited table and write
    the LLM analysis two rows below the selection.

    Attempts to merge the output row across the selection width so the
    analysis reads as a single block rather than a single narrow cell.
    """
    api_type = str(job.get_config("api_type", "completions")).lower()
    system_prompt = (
        "Tu es un analyste de données expert. "
        "Tu analyses des tableaux et fournis des insights concis et actionnables en français."
    )

    rows_text = []
    for row in row_range:
        cells = [sheet.getCellByPosition(col, row).getString() for col in col_range]
        row_str = " | ".join(cells)
        if row_str.replace("|", "").strip():
            rows_text.append(row_str)
    table_text = "\n".join(rows_text)

    if not table_text:
        return

    prompt = (
        "Voici un tableau de données :\n\n"
        + table_text
        + "\n\nAnalyse ces données : tendances, anomalies, points notables. "
        "Sois concis et factuel.\n\nANALYSE :"
    )

    out_row = row_range.stop + 1
    out_col = col_range.start
    result_cell = sheet.getCellByPosition(out_col, out_row)
    result_cell.setString("")

    # Merge output row across the selection width for readability
    n_cols = col_range.stop - col_range.start
    if n_cols > 1:
        try:
            cell_range = sheet.getCellRangeByPosition(
                out_col, out_row, out_col + n_cols - 1, out_row
            )
            cell_range.merge(True)
        except Exception:
            pass

    try:
        request = job.make_api_request(prompt, system_prompt, 1000, api_type=api_type)

        def append_analysis(chunk_text, rc=result_cell):
            rc.setString(rc.getString() + chunk_text)

        job.stream_request(request, api_type, append_analysis)
    except Exception as e:
        result_cell.setString(_ERR_PREFIX + str(e))


def handle_calc_action(job, args, model):
    if not hasattr(model, "Sheets"):
        return False

    job._log("Processing Calc document")
    try:
        sheet = model.CurrentController.ActiveSheet
        selection = model.CurrentController.Selection

        if args == "settings":
            _open_settings(job)
            return True

        # Collect user input before touching the sheet
        user_input = ""
        if args == "EditSelection":
            user_input = job.input_box(
                "Saisissez vos instructions d'édition !",
                "Modifier la sélection",
                "",
                ok_label="Envoyer",
                cancel_label="Fermer",
                always_on_top=True,
            )
        elif args == "TransformToColumn":
            user_input = job.input_box(
                "Quelle transformation appliquer à chaque cellule ?",
                "Transformer → colonne résultat",
                "",
                ok_label="Transformer",
                cancel_label="Annuler",
                always_on_top=True,
            )
        elif args == "GenerateFormula":
            user_input = job.input_box(
                "Décrivez la formule souhaitée :",
                "Générer une formule",
                "",
                ok_label="Générer",
                cancel_label="Annuler",
                always_on_top=True,
            )

        # GenerateFormula only needs the active cell, not a range
        if args == "GenerateFormula":
            if user_input:
                area = selection.getRangeAddress()
                target_cell = sheet.getCellByPosition(area.StartColumn, area.StartRow)
                _generate_formula(job, target_cell, user_input)
            return True

        area = selection.getRangeAddress()
        start_row = area.StartRow
        end_row = area.EndRow
        start_col = area.StartColumn
        end_col = area.EndColumn

        col_range = range(start_col, end_col + 1)
        row_range = range(start_row, end_row + 1)

        if args == "ExtendSelection":
            _extend_cells(job, sheet, col_range, row_range)
        elif args == "EditSelection":
            _edit_cells(job, sheet, col_range, row_range, user_input)
        elif args == "TransformToColumn":
            if user_input:
                _transform_to_column(job, sheet, col_range, row_range, user_input)
        elif args == "AnalyzeRange":
            _analyze_range(job, sheet, col_range, row_range)
    except Exception:
        pass

    return True
