#!/usr/bin/env python3
"""
Generate tests/fixtures/sample_calc.ods — test fixture for Calc MIrAI actions.

Layout (Calc row numbers, 1-based):
  Section A — TransformToColumn  : données en A4:A8  → résultats en B4:B8
  Section B — GenerateFormula    : données en A14:A18, formule cible C14
  Section C — AnalyzeRange       : tableau en A23:D27, analyse en A29
"""
import io
import zipfile
import sys
from pathlib import Path

OUT = Path(__file__).parent.parent / "tests" / "fixtures" / "sample_calc.ods"


# ---------------------------------------------------------------------------
# ODS is a ZIP containing at minimum: mimetype + META-INF/manifest.xml + content.xml
# ---------------------------------------------------------------------------

MIMETYPE = b"application/vnd.oasis.opendocument.spreadsheet"

MANIFEST = """\
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
                   manifest:version="1.2">
  <manifest:file-entry manifest:media-type="application/vnd.oasis.opendocument.spreadsheet"
                       manifest:version="1.2" manifest:full-path="/"/>
  <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml"/>
  <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="styles.xml"/>
</manifest:manifest>
"""

STYLES = """\
<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  office:version="1.2"/>
"""


def _cell(value=""):
    """Return one <table:table-cell> XML fragment.

    Numeric strings are stored as float so formulas (AVERAGE, SUM…) work.
    """
    if not value and value != 0:
        return "<table:table-cell/>"
    try:
        num = float(value)
        return (
            f'<table:table-cell office:value-type="float" office:value="{num}">'
            f"<text:p>{value}</text:p>"
            "</table:table-cell>"
        )
    except (ValueError, TypeError):
        return (
            '<table:table-cell office:value-type="string">'
            f"<text:p>{value}</text:p>"
            "</table:table-cell>"
        )


def _row(*cells):
    inner = "".join(_cell(c) for c in cells)
    return f"<table:table-row>{inner}</table:table-row>"


def _empty_rows(n):
    return f'<table:table-row table:number-rows-repeated="{n}"><table:table-cell/></table:table-row>'


def build_content():
    rows = []

    # ── Section A : TransformToColumn ─────────────────────────────────────────
    # Calc rows 1-10  (0-indexed 0-9)
    rows.append(_row("=== Section A : Transformer → colonne résultat ==="))
    rows.append(_row(
        "Sélectionner A4:A8 → MIrAI → Transformer → colonne résultat",
        "", "Instruction : « Traduire en anglais »  — résultat → col B"
    ))
    rows.append(_row("Ville (source)", "← Résultat ici après transformation"))
    rows.append(_row("Paris"))       # A4
    rows.append(_row("Lyon"))        # A5
    rows.append(_row("Marseille"))   # A6
    rows.append(_row("Bordeaux"))    # A7
    rows.append(_row("Nice"))        # A8
    rows.append(_empty_rows(1))      # row 9
    rows.append(_empty_rows(1))      # row 10

    # ── Section B : GenerateFormula ───────────────────────────────────────────
    # Calc rows 11-20  (0-indexed 10-19)
    rows.append(_row("=== Section B : Générer une formule ==="))
    rows.append(_row(
        "Cliquer sur C14 (vide) → MIrAI → Générer une formule",
        "", "Description : « moyenne de A14 à A18 »  — attendu : 30"
    ))
    rows.append(_row("Données", "Carré", "← Formule en C14 (vide)"))
    rows.append(_row("10", "100"))   # A14 — C14 intentionally empty (formula target)
    rows.append(_row("20", "400"))   # A15
    rows.append(_row("30", "900"))   # A16
    rows.append(_row("40", "1600"))  # A17
    rows.append(_row("50", "2500"))  # A18
    rows.append(_empty_rows(1))      # row 19
    rows.append(_empty_rows(1))      # row 20

    # ── Section C : AnalyzeRange ──────────────────────────────────────────────
    # Calc rows 21-29  (0-indexed 20-28)
    rows.append(_row("=== Section C : Analyser la plage ==="))
    rows.append(_row(
        "Sélectionner A23:D27 (en-têtes inclus) → MIrAI → Analyser la plage",
        "", "↓ Analyse LLM en A29"
    ))
    rows.append(_row("Produit",     "Jan",  "Fév",  "Mar"))   # A23 headers
    rows.append(_row("Baguettes",   "1200", "980",  "1350"))  # A24
    rows.append(_row("Croissants",  "870",  "910",  "760"))   # A25
    rows.append(_row("Pains spéc.", "430",  "510",  "620"))   # A26
    rows.append(_row("Brioches",    "210",  "190",  "310"))   # A27
    rows.append(_empty_rows(1))      # row 28 (buffer before analysis output)
    # row 29 = A29 : analysis written here by AnalyzeRange

    content = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content
  xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  office:version="1.2">
  <office:body>
    <office:spreadsheet>
      <table:table table:name="Tests MIrAI Calc">
        {"".join(rows)}
      </table:table>
    </office:spreadsheet>
  </office:body>
</office:document-content>
"""
    return content


def main():
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
    out_path.parent.mkdir(parents=True, exist_ok=True)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # mimetype MUST be first and MUST be stored (no compression)
        zf.writestr(
            zipfile.ZipInfo("mimetype"),
            MIMETYPE,
            compress_type=zipfile.ZIP_STORED,
        )
        zf.writestr("META-INF/manifest.xml", MANIFEST)
        zf.writestr("styles.xml", STYLES)
        zf.writestr("content.xml", build_content())

    out_path.write_bytes(buf.getvalue())
    print(f"Created: {out_path}")


if __name__ == "__main__":
    main()
