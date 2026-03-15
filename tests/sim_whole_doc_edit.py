#!/usr/bin/env python3
"""Simulate the whole-doc edit pipeline without LibreOffice.

Tests: chunking, numbered-paragraph prompt, FIND/REPLACE parsing with
multiline split and [Pn] stripping, search/replace application.
"""
import re
import textwrap

# ─── Simulated document ─────────────────────────────────────────────────────
SAMPLE_PARAGRAPHS = [
    {"text": "Rapport annuel 2024",                  "style": "Heading 1", "page_break": False},
    {"text": "",                                      "style": "Default",   "page_break": False},
    {"text": "Introduction",                          "style": "Heading 2", "page_break": False},
    {"text": "Ce document présente les résultats de l'année 2024. "
             "Il couvre les activités principales du ministère.",
                                                      "style": "Default",   "page_break": False},
    {"text": "Les objectifs fixés ont été largement atteints. "
             "La transformation numérique progresse.",
                                                      "style": "Default",   "page_break": False},
    {"text": "",                                      "style": "Default",   "page_break": False},
    {"text": "Chapitre 1 : Sécurité",                "style": "Heading 2", "page_break": True},
    {"text": "La sécurité reste une priorité absolue pour le ministère. "
             "Plusieurs mesures ont été déployées en 2024.",
                                                      "style": "Default",   "page_break": False},
    {"text": "Le nombre d'incidents a diminué de 30% par rapport à 2023.",
                                                      "style": "Default",   "page_break": False},
    {"text": "Les équipes ont été renforcées avec 50 nouveaux agents.",
                                                      "style": "Default",   "page_break": False},
    {"text": "",                                      "style": "Default",   "page_break": False},
    {"text": "Chapitre 2 : Innovation",               "style": "Heading 2", "page_break": True},
    {"text": "L'innovation est au cœur de la stratégie ministérielle. "
             "De nouveaux outils ont été mis en place.",
                                                      "style": "Default",   "page_break": False},
    {"text": "Le projet MIrAI a permis d'intégrer l'intelligence artificielle "
             "dans les processus quotidiens.",
                                                      "style": "Default",   "page_break": False},
    {"text": "Plus de 200 agents utilisent désormais l'assistant IA.",
                                                      "style": "Default",   "page_break": False},
    {"text": "",                                      "style": "Default",   "page_break": False},
    {"text": "Conclusion",                            "style": "Heading 2", "page_break": False},
    {"text": "L'année 2024 a été marquée par des avancées significatives. "
             "Le ministère poursuit sa modernisation.",
                                                      "style": "Default",   "page_break": False},
    {"text": "Les perspectives pour 2025 sont encourageantes.",
                                                      "style": "Default",   "page_break": False},
]


# ─── 1. Chunking logic (matches entrypoint.py) ──────────────────────────────
def chunk_paragraphs(paragraphs, chunk_max=3000):
    if not paragraphs:
        return []

    chunks = []
    current_chunk = []
    current_len = 0
    prev_style = paragraphs[0]["style"]

    for p in paragraphs:
        p_len = len(p["text"]) + 1

        should_break = False
        if current_len > 0:
            if p["page_break"]:
                should_break = True
            elif current_len + p_len > chunk_max:
                should_break = True
            elif current_len > chunk_max * 0.6:
                if p["style"] != prev_style:
                    should_break = True
                elif p["text"].strip() == "":
                    should_break = True
                elif current_chunk and current_chunk[-1]["text"].rstrip().endswith(
                        (".", "!", "?", "\u2026", ";")):
                    should_break = True

        if should_break and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_len = 0

        current_chunk.append(p)
        current_len += p_len
        prev_style = p["style"]

    if current_chunk:
        chunks.append(current_chunk)

    return chunks


# ─── 2. Build numbered prompt (matches entrypoint.py fix) ───────────────────
def build_chunk_text(chunk):
    """Build numbered paragraph list, skipping empty paragraphs."""
    numbered = []
    for i, p in enumerate(chunk):
        if p["text"].strip():
            numbered.append(f"[P{i+1}] {p['text']}")
    return "\n".join(numbered)


# ─── 3. FIND/REPLACE parser (matches entrypoint.py fix) ─────────────────────
def parse_find_replace(text):
    """Parse <<<FIND>>>...<<<REPLACE>>>...<<<END>>> with multiline split + [Pn] strip."""
    raw_blocks = re.findall(
        r'<<<FIND>>>\s*\n?(.*?)<<<REPLACE>>>\s*\n?(.*?)<<<END>>>',
        text, re.DOTALL,
    )
    _strip_pn = re.compile(r'^\[P\d+\]\s*', re.MULTILINE)
    result = []
    for f_raw, r_raw in raw_blocks:
        f_clean = _strip_pn.sub('', f_raw).strip()
        r_clean = _strip_pn.sub('', r_raw).strip()
        if not f_clean:
            continue
        f_lines = f_clean.split('\n')
        r_lines = r_clean.split('\n')
        if len(f_lines) > 1:
            for i, fl in enumerate(f_lines):
                fl = fl.strip()
                if not fl:
                    continue
                rl = r_lines[i].strip() if i < len(r_lines) else fl
                result.append((fl, rl))
        else:
            result.append((f_clean, r_clean))
    return result


# ─── 4. Simulated document ──────────────────────────────────────────────────
class SimulatedDoc:
    def __init__(self, paragraphs):
        self.paragraphs = [dict(p) for p in paragraphs]

    def find_and_replace(self, find_text, replace_text):
        for p in self.paragraphs:
            if find_text in p["text"]:
                p["text"] = p["text"].replace(find_text, replace_text, 1)
                return True
        return False

    def get_full_text(self):
        return "\n".join(p["text"] for p in self.paragraphs)


# ─── 5. LLM simulators ──────────────────────────────────────────────────────
TRANSLATIONS = {
    "Rapport annuel 2024": "Annual Report 2024",
    "Introduction": "Introduction",  # same — should be NOCHANGE
    "Ce document présente les résultats de l'année 2024. Il couvre les activités principales du ministère.":
        "This document presents the results of the year 2024. It covers the ministry's main activities.",
    "Les objectifs fixés ont été largement atteints. La transformation numérique progresse.":
        "The set objectives have been largely achieved. Digital transformation is progressing.",
    "Chapitre 1 : Sécurité": "Chapter 1: Security",
    "La sécurité reste une priorité absolue pour le ministère. Plusieurs mesures ont été déployées en 2024.":
        "Security remains an absolute priority for the ministry. Several measures were deployed in 2024.",
    "Le nombre d'incidents a diminué de 30% par rapport à 2023.":
        "The number of incidents decreased by 30% compared to 2023.",
    "Les équipes ont été renforcées avec 50 nouveaux agents.":
        "Teams were strengthened with 50 new agents.",
    "Chapitre 2 : Innovation": "Chapter 2: Innovation",
    "L'innovation est au cœur de la stratégie ministérielle. De nouveaux outils ont été mis en place.":
        "Innovation is at the heart of the ministerial strategy. New tools have been implemented.",
    "Le projet MIrAI a permis d'intégrer l'intelligence artificielle dans les processus quotidiens.":
        "The MIrAI project enabled the integration of artificial intelligence into daily processes.",
    "Plus de 200 agents utilisent désormais l'assistant IA.":
        "More than 200 agents now use the AI assistant.",
    "Conclusion": "Conclusion",  # same
    "L'année 2024 a été marquée par des avancées significatives. Le ministère poursuit sa modernisation.":
        "The year 2024 was marked by significant advances. The ministry continues its modernization.",
    "Les perspectives pour 2025 sont encourageantes.":
        "The perspectives for 2025 are encouraging.",
}


def simulate_llm_good_numbered(chunk_text):
    """LLM that respects numbered paragraphs and produces one block per paragraph."""
    blocks = []
    for line in chunk_text.split("\n"):
        # Extract text after [Pn]
        m = re.match(r'\[P\d+\]\s*(.*)', line)
        if not m:
            continue
        original = m.group(1).strip()
        if original in TRANSLATIONS and TRANSLATIONS[original] != original:
            blocks.append(
                f"<<<FIND>>>\n{original}\n<<<REPLACE>>>\n{TRANSLATIONS[original]}\n<<<END>>>"
            )
    return "\n\n".join(blocks) if blocks else "<<<NOCHANGE>>>"


def simulate_llm_multiline_merge(chunk_text):
    """LLM that merges multiple paragraphs into one FIND (the bug we're fixing)."""
    lines = chunk_text.split("\n")
    originals = []
    replacements = []
    for line in lines:
        m = re.match(r'\[P\d+\]\s*(.*)', line)
        if not m:
            continue
        original = m.group(1).strip()
        if original in TRANSLATIONS and TRANSLATIONS[original] != original:
            originals.append(original)
            replacements.append(TRANSLATIONS[original])
    if not originals:
        return "<<<NOCHANGE>>>"
    # Merge ALL into one block (the bug)
    return (
        f"<<<FIND>>>\n" + "\n".join(originals) +
        f"\n<<<REPLACE>>>\n" + "\n".join(replacements) +
        f"\n<<<END>>>"
    )


def simulate_llm_with_pn_echo(chunk_text):
    """LLM that echoes [Pn] markers in FIND/REPLACE (the parser should strip them)."""
    blocks = []
    for line in chunk_text.split("\n"):
        m = re.match(r'(\[P\d+\])\s*(.*)', line)
        if not m:
            continue
        pn, original = m.group(1), m.group(2).strip()
        if original in TRANSLATIONS and TRANSLATIONS[original] != original:
            blocks.append(
                f"<<<FIND>>>\n{pn} {original}\n<<<REPLACE>>>\n{pn} {TRANSLATIONS[original]}\n<<<END>>>"
            )
    return "\n\n".join(blocks) if blocks else "<<<NOCHANGE>>>"


# ─── 6. Tests ────────────────────────────────────────────────────────────────
def run_pipeline(doc, chunks, llm_func, label):
    print(f"\n{'=' * 70}")
    print(f"TEST: {label}")
    print(f"{'=' * 70}")

    total_replacements = 0
    total_not_found = 0

    for i, chunk in enumerate(chunks):
        chunk_text = build_chunk_text(chunk)
        if not chunk_text.strip():
            continue

        llm_response = llm_func(chunk_text)
        if "<<<NOCHANGE>>>" in llm_response:
            print(f"  Chunk {i+1}: NOCHANGE")
            continue

        replacements = parse_find_replace(llm_response)
        print(f"  Chunk {i+1}: {len(replacements)} replacement(s)")

        for find_text, replace_text in replacements:
            ok = doc.find_and_replace(find_text, replace_text)
            if ok:
                total_replacements += 1
            else:
                total_not_found += 1
                print(f"    *** NOT FOUND: {find_text[:60]}...")

    print(f"\n  Replacements: {total_replacements} | Not found: {total_not_found}")

    # Check result
    french_words = ["Ce document", "Les objectifs", "La sécurité", "L'innovation",
                    "L'année", "Les perspectives", "Le nombre", "Les équipes",
                    "Le projet MIrAI", "Plus de 200", "Chapitre", "Rapport annuel"]
    remaining = [w for w in french_words if w in doc.get_full_text()]
    if remaining:
        print(f"  REMAINING FRENCH: {remaining}")
    else:
        print(f"  OK: all French text translated")

    return total_replacements, total_not_found


def test_prompt_format():
    print("=" * 70)
    print("TEST: PROMPT FORMAT (what the LLM sees)")
    print("=" * 70)

    chunks = chunk_paragraphs(SAMPLE_PARAGRAPHS, chunk_max=3000)
    for i, chunk in enumerate(chunks):
        chunk_text = build_chunk_text(chunk)
        print(f"\n  --- Chunk {i+1} ({len(chunk)} paras, {len(chunk_text)} chars) ---")
        for line in chunk_text.split("\n"):
            print(f"  | {line}")
    print()
    print("  Empty paragraphs are filtered out.")
    print("  Each paragraph is numbered [P1], [P2], etc.")
    print("  LLM can clearly see paragraph boundaries.")


def test_parser_pn_strip():
    print("\n" + "=" * 70)
    print("TEST: PARSER [Pn] STRIPPING")
    print("=" * 70)

    # LLM echoes [P1] in FIND
    response = "<<<FIND>>>\n[P1] Bonjour le monde\n<<<REPLACE>>>\n[P1] Hello world\n<<<END>>>"
    result = parse_find_replace(response)
    print(f"  Input:  [P1] Bonjour le monde → [P1] Hello world")
    print(f"  Parsed: {result}")
    assert result == [("Bonjour le monde", "Hello world")], f"Unexpected: {result}"
    print("  OK: [Pn] stripped correctly")


def test_parser_multiline_split():
    print("\n" + "=" * 70)
    print("TEST: PARSER MULTILINE SPLIT")
    print("=" * 70)

    # LLM merges two paragraphs
    response = (
        "<<<FIND>>>\nBonjour le monde\nAu revoir\n"
        "<<<REPLACE>>>\nHello world\nGoodbye\n<<<END>>>"
    )
    result = parse_find_replace(response)
    print(f"  Input:  multiline FIND (2 lines)")
    print(f"  Parsed: {result}")
    assert len(result) == 2, f"Expected 2 pairs, got {len(result)}"
    assert result[0] == ("Bonjour le monde", "Hello world")
    assert result[1] == ("Au revoir", "Goodbye")
    print("  OK: multiline FIND split into 2 per-line pairs")

    # Mismatched line count (more FIND than REPLACE)
    response2 = (
        "<<<FIND>>>\nLine A\nLine B\nLine C\n"
        "<<<REPLACE>>>\nTranslated A\nTranslated B\n<<<END>>>"
    )
    result2 = parse_find_replace(response2)
    print(f"\n  Mismatched lines (3 FIND, 2 REPLACE): {result2}")
    assert len(result2) == 3
    assert result2[2] == ("Line C", "Line C")  # fallback: keep original
    print("  OK: missing REPLACE line falls back to original text")


def test_full_pipeline_good():
    doc = SimulatedDoc(SAMPLE_PARAGRAPHS)
    chunks = chunk_paragraphs(SAMPLE_PARAGRAPHS, chunk_max=3000)
    repl, notfound = run_pipeline(doc, chunks, simulate_llm_good_numbered,
                                  "GOOD LLM (numbered paragraphs)")
    print("\n  --- Final document ---")
    for p in doc.paragraphs:
        if p["text"]:
            print(f"  [{p['style']}] {p['text']}")


def test_full_pipeline_multiline():
    doc = SimulatedDoc(SAMPLE_PARAGRAPHS)
    chunks = chunk_paragraphs(SAMPLE_PARAGRAPHS, chunk_max=3000)
    repl, notfound = run_pipeline(doc, chunks, simulate_llm_multiline_merge,
                                  "BUGGY LLM (multiline merge) + SPLIT FIX")
    print("\n  --- Final document ---")
    for p in doc.paragraphs:
        if p["text"]:
            print(f"  [{p['style']}] {p['text']}")


def test_full_pipeline_pn_echo():
    doc = SimulatedDoc(SAMPLE_PARAGRAPHS)
    chunks = chunk_paragraphs(SAMPLE_PARAGRAPHS, chunk_max=3000)
    repl, notfound = run_pipeline(doc, chunks, simulate_llm_with_pn_echo,
                                  "LLM ECHOES [Pn] + STRIP FIX")


# ─── Run all tests ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_prompt_format()
    test_parser_pn_strip()
    test_parser_multiline_split()
    test_full_pipeline_good()
    test_full_pipeline_multiline()
    test_full_pipeline_pn_echo()

    print("\n" + "=" * 70)
    print("ALL TESTS PASSED" if True else "")
    print("=" * 70)
