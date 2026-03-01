"""Calc menu actions extracted from MainJob.trigger."""

from .shared import apply_settings_result


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
    except Exception:
        pass

    return True

