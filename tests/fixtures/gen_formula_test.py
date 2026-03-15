#!/usr/bin/env python3
"""Generate tests/fixtures/formula_test.ods — a spreadsheet suited for testing
the GenerateFormula, TransformToColumn, AnalyzeRange and ExtendSelection actions.
"""
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow, TableCell, TableColumn
from odf.text import P
from odf.style import Style, TableCellProperties, TextProperties, TableColumnProperties, TableRowProperties

doc = OpenDocumentSpreadsheet()

# ── Column / row styles ───────────────────────────────────────────────────────
def _col_style(name, width):
    s = Style(name=name, family="table-column")
    s.addElement(TableColumnProperties(columnwidth=width))
    doc.automaticstyles.addElement(s)

def _row_style(name, optimal=True, height=None):
    s = Style(name=name, family="table-row")
    kw = {"useoptimalrowheight": "true" if optimal else "false"}
    if height:
        kw["rowheight"] = height
    s.addElement(TableRowProperties(**kw))
    doc.automaticstyles.addElement(s)

_col_style("ColLabel", "5.5cm")
_col_style("ColText",  "13cm")
_col_style("ColData",  "3cm")
_row_style("RowAuto",   optimal=True)
_row_style("RowTitle",  optimal=False, height="0.9cm")

# ── Styles ────────────────────────────────────────────────────────────────────
def _add_style(name, bg, fg="#000000", bold=False, wrap=False, border=None, valign="top"):
    s = Style(name=name, family="table-cell")
    cp = {"backgroundcolor": bg, "verticalalign": valign}
    if wrap:
        cp["wrapoption"] = "wrap"
    if border:
        cp["border"] = border
    s.addElement(TableCellProperties(**cp))
    tp = {"color": fg}
    if bold:
        tp["fontweight"] = "bold"
    s.addElement(TextProperties(**tp))
    doc.automaticstyles.addElement(s)

_add_style("HeaderCell",     bg="#4472C4", fg="#FFFFFF", bold=True)
_add_style("CartoucheTitle", bg="#1F3864", fg="#FFFFFF", bold=True, wrap=True)
_add_style("CartoucheStep",  bg="#D9E2F3", fg="#1F3864", bold=True, wrap=True)
_add_style("CartoucheText",  bg="#EEF2F9", fg="#222222", wrap=True, border="0.05pt solid #4472C4")
_add_style("CartoucheNote",  bg="#FFF2CC", fg="#7F6000", wrap=True, border="0.05pt solid #F0C040")

def make_cell(value, stylename=None):
    """Create a cell — numeric if value is a number, string otherwise."""
    try:
        num = float(value)
        kw = {"valuetype": "float", "value": str(num)}
    except (TypeError, ValueError):
        kw = {"valuetype": "string"}
    if stylename:
        kw["stylename"] = stylename
    tc = TableCell(**kw)
    tc.addElement(P(text=str(value)))
    return tc

def make_row(values, styles=None, row_style=None):
    kw = {"stylename": row_style} if row_style else {}
    row = TableRow(**kw)
    styles = styles or []
    for i, v in enumerate(values):
        st = styles[i] if i < len(styles) else None
        row.addElement(make_cell(v, stylename=st))
    return row

def blank_row(n=1):
    row = TableRow(stylename="RowTitle")
    for _ in range(n):
        row.addElement(TableCell())
    return row

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 0 : INSTRUCTIONS
# ─────────────────────────────────────────────────────────────────────────────
instructions = Table(name="Instructions")

# Column widths for instructions sheet
instructions.addElement(TableColumn(stylename="ColLabel"))
instructions.addElement(TableColumn(stylename="ColText"))

def instr_row(label, text, label_style="CartoucheStep", text_style="CartoucheText"):
    row = TableRow(stylename="RowAuto")
    row.addElement(make_cell(label, stylename=label_style))
    row.addElement(make_cell(text,  stylename=text_style))
    return row

# Title banner
instructions.addElement(make_row(
    ["MIrAI — Guide de tests rapides", ""],
    styles=["CartoucheTitle", "CartoucheTitle"],
    row_style="RowTitle",
))
instructions.addElement(blank_row(2))

# ── Feuille Ventes ──
instructions.addElement(make_row(
    ["FEUILLE « Ventes »", ""],
    styles=["CartoucheTitle", "CartoucheTitle"],
    row_style="RowTitle",
))
instructions.addElement(instr_row(
    "TEST 1 — Générer une formule (1 cellule)",
    "1. Aller sur la feuille Ventes\n"
    "2. Cliquer sur G2 (colonne Total, ligne Alice)\n"
    "3. Menu MIrAI → Générer une formule\n"
    "4. Saisir : somme des colonnes T1 à T4 pour cette ligne\n"
    "5. Cliquer ⚡ Générer\n"
    "✅ Attendu : G2 affiche =SUM(C2:F2) et la valeur 55 500",
))
instructions.addElement(instr_row(
    "TEST 2 — Générer une formule (plage G2:G9)",
    "1. Sélectionner G2:G9\n"
    "2. Menu MIrAI → Générer une formule\n"
    "3. Saisir : somme des colonnes T1 à T4\n"
    "4. Cliquer ⚡ Générer\n"
    "✅ Attendu : toutes les lignes G2 à G9 remplies avec =SUM(Cx:Fx)",
))
instructions.addElement(instr_row(
    "TEST 3 — Multi-tour (affiner)",
    "1. Cliquer sur H2 (colonne Croissance)\n"
    "2. Menu MIrAI → Générer une formule\n"
    "3. Tour 1 : croissance entre T1 et T4 en pourcentage\n"
    "4. Tour 2 (si erreur) : rends la robuste avec IFERROR\n"
    "✅ Attendu : dialogue rouvre avec historique, formule corrigée",
))
instructions.addElement(instr_row(
    "TEST 4 — Analyser la plage",
    "1. Sélectionner A1:F9\n"
    "2. Menu MIrAI → Analyser la plage\n"
    "✅ Attendu : analyse en français 2 lignes sous la sélection, cellules fusionnées",
))
instructions.addElement(blank_row(2))

# ── Feuille Villes ──
instructions.addElement(make_row(
    ["FEUILLE « Villes »", ""],
    styles=["CartoucheTitle", "CartoucheTitle"],
    row_style="RowTitle",
))
instructions.addElement(instr_row(
    "TEST 5 — TransformToColumn",
    "1. Sélectionner A2:A11 (les 10 villes)\n"
    "2. Menu MIrAI → Transformer les cellules\n"
    "3. Instruction : pays correspondant à cette ville\n"
    "✅ Attendu : colonne B remplie, cellules auto-dimensionnées",
))
instructions.addElement(blank_row(2))

# ── Feuille Textes ──
instructions.addElement(make_row(
    ["FEUILLE « Textes »", ""],
    styles=["CartoucheTitle", "CartoucheTitle"],
    row_style="RowTitle",
))
instructions.addElement(instr_row(
    "TEST 6 — Étendre la sélection",
    "1. Sélectionner A2:A5\n"
    "2. Menu MIrAI → Étendre la sélection\n"
    "✅ Attendu : chaque texte est allongé en streaming",
))
instructions.addElement(instr_row(
    "TEST 7 — Modifier la sélection",
    "1. Sélectionner A2:A5\n"
    "2. Menu MIrAI → Modifier la sélection\n"
    "3. Instruction : traduis en anglais\n"
    "✅ Attendu : textes remplacés par leur traduction",
))
instructions.addElement(blank_row(2))

instructions.addElement(instr_row(
    "NOTE",
    "Les logs temps-réel sont dans ~/log.txt\n"
    "Les formules utilisent les noms anglais (SUM, IF, VLOOKUP…) et le séparateur « ; »",
    label_style="CartoucheNote", text_style="CartoucheNote",
))

doc.spreadsheet.addElement(instructions)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 1 : Ventes
# ─────────────────────────────────────────────────────────────────────────────
sheet1 = Table(name="Ventes")
headers = ["Nom", "Région", "T1", "T2", "T3", "T4", "Total", "Croissance"]
for _ in headers:
    sheet1.addElement(TableColumn(stylename="ColData"))
sheet1.addElement(make_row(headers, styles=["HeaderCell"] * len(headers), row_style="RowTitle"))

data = [
    ("Alice",    "Nord",  12000, 13500, 14200, 15800, "", ""),
    ("Bob",      "Sud",   9800,  10200, 11000, 10500, "", ""),
    ("Carol",    "Est",   15000, 14800, 16200, 17000, "", ""),
    ("David",    "Ouest", 8500,  9200,  9800,  11200, "", ""),
    ("Élodie",   "Nord",  13200, 13800, 14500, 15200, "", ""),
    ("François", "Sud",   11000, 11500, 12300, 12800, "", ""),
    ("Grace",    "Est",   7800,  8200,  8900,  9500,  "", ""),
    ("Hamid",    "Ouest", 16000, 15500, 17200, 18000, "", ""),
]
for row_data in data:
    sheet1.addElement(make_row(row_data))

doc.spreadsheet.addElement(sheet1)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 2 : Villes
# ─────────────────────────────────────────────────────────────────────────────
sheet2 = Table(name="Villes")
sheet2.addElement(make_row(["Ville", "Pays"], styles=["HeaderCell", "HeaderCell"]))

cities = ["Paris", "Berlin", "Rome", "Madrid", "Amsterdam",
          "Bruxelles", "Lisbonne", "Vienne", "Varsovie", "Prague"]
for city in cities:
    sheet2.addElement(make_row([city, ""]))

doc.spreadsheet.addElement(sheet2)

# ─────────────────────────────────────────────────────────────────────────────
# Sheet 3 : Textes
# ─────────────────────────────────────────────────────────────────────────────
sheet3 = Table(name="Textes")
sheet3.addElement(make_row(["Description"], styles=["HeaderCell"]))
texts = [
    "Le chiffre d'affaires a augmenté ce trimestre",
    "Les ventes en région Nord sont en hausse",
    "Plusieurs clients ont renouvelé leur contrat",
    "La marge brute reste stable malgré la hausse des coûts",
]
for t in texts:
    sheet3.addElement(make_row([t]))

doc.spreadsheet.addElement(sheet3)

# ─────────────────────────────────────────────────────────────────────────────
out = "tests/fixtures/formula_test.ods"
doc.save(out)
print(f"Written: {out}")
