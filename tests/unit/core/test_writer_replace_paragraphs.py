"""`writer_replace_paragraphs` — le pendant écriture de la carte du document.

Sans cet outil, le moteur savait LIRE le document numéroté ([P1], [P2]…) mais
n'avait aucun moyen d'agir dessus hors sélection. Une demande du type
« restructure ce document en deux paragraphes » recevait alors une réponse en
texte, le document restant inchangé — l'utilisateur voyait « il ne se passe
rien » alors que le run se terminait en succès.
"""

from src.mirai.core.context import ToolContext
from src.mirai.core.tools.writer_tools import replace_paragraphs
from tests.stubs.fake_shell import FakeShell


class FakeParagraph:
    def __init__(self, doc, index):
        self._doc = doc
        self._index = index

    def supportsService(self, name):
        return name == "com.sun.star.text.Paragraph"

    def getString(self):
        return self._doc.paragraphs[self._index]

    def getStart(self):
        return ("start", self._index)

    def getEnd(self):
        return ("end", self._index)


class FakeCursor:
    def __init__(self, doc, start):
        self._doc = doc
        self._start = start[1]
        self._end = start[1]

    def gotoRange(self, target, _expand):
        self._end = target[1]

    def setString(self, text):
        replacement = text.split("\n")
        self._doc.paragraphs[self._start:self._end + 1] = replacement


class FakeText:
    def __init__(self, doc):
        self._doc = doc

    def createEnumeration(self):
        return iter(FakeEnumeration(self._doc))

    def createTextCursorByRange(self, position):
        return FakeCursor(self._doc, position)


class FakeEnumeration:
    def __init__(self, doc):
        self._items = [FakeParagraph(doc, i) for i in range(len(doc.paragraphs))]

    def __iter__(self):
        return iter(self._items)

    def hasMoreElements(self):
        return bool(self._items)

    def nextElement(self):
        return self._items.pop(0)


class FakeDoc:
    """Document Writer à état réel : les remplacements sont observables."""

    def __init__(self, paragraphs):
        self.paragraphs = list(paragraphs)
        self.Text = FakeText(self)

    def getUndoManager(self):
        return self

    def enterUndoContext(self, _label):
        pass

    def leaveUndoContext(self):
        pass


def _ctx(paragraphs):
    doc = FakeDoc(paragraphs)
    # `Text.createEnumeration` doit rendre un objet neuf à chaque appel.
    doc.Text.createEnumeration = lambda: FakeEnumeration(doc)
    return ToolContext(None, doc, object(), "writer", FakeShell()), doc


def test_replaces_a_single_paragraph():
    ctx, doc = _ctx(["Premier.", "Deuxième.", "Troisième."])

    result = replace_paragraphs(ctx, {"start": 2, "text": "Remplacé."})

    assert result.ok
    assert doc.paragraphs == ["Premier.", "Remplacé.", "Troisième."]


def test_replaces_a_range():
    ctx, doc = _ctx(["A", "B", "C", "D"])

    result = replace_paragraphs(ctx, {"start": 2, "end": 3, "text": "Fusion."})

    assert result.ok
    assert doc.paragraphs == ["A", "Fusion.", "D"]
    assert result.data["replaced"] == 2


def test_newlines_create_paragraphs():
    """Le cas qui motive l'outil : « restructure en deux paragraphes »."""
    ctx, doc = _ctx(["Un.", "Deux.", "Trois.", "Quatre.", "Cinq."])

    result = replace_paragraphs(
        ctx, {"start": 1, "end": 5, "text": "Bloc un.\nBloc deux."})

    assert result.ok
    assert doc.paragraphs == ["Bloc un.", "Bloc deux."]


def test_end_is_clamped_to_the_document():
    """Un modèle qui vise trop loin ne doit pas faire échouer l'opération."""
    ctx, doc = _ctx(["A", "B"])

    result = replace_paragraphs(ctx, {"start": 1, "end": 99, "text": "Tout."})

    assert result.ok
    assert doc.paragraphs == ["Tout."]


def test_start_beyond_the_document_is_refused():
    ctx, doc = _ctx(["A", "B"])

    result = replace_paragraphs(ctx, {"start": 7, "text": "X"})

    assert not result.ok
    assert "2 paragraphe" in result.error
    assert doc.paragraphs == ["A", "B"], "le document ne doit pas être touché"


def test_invalid_range_is_refused():
    ctx, doc = _ctx(["A", "B", "C"])

    assert not replace_paragraphs(ctx, {"start": 0, "text": "X"}).ok
    assert not replace_paragraphs(ctx, {"start": 3, "end": 2, "text": "X"}).ok
    assert doc.paragraphs == ["A", "B", "C"]


def test_tool_is_registered_for_writer():
    """Sans enregistrement, l'outil serait invisible pour le modèle."""
    from src.mirai.core.registry import ToolRegistry
    from src.mirai.core.tools import register_all

    names = [t["function"]["name"]
             for t in register_all(ToolRegistry()).openai_tools("writer")]
    assert "writer_replace_paragraphs" in names


def test_tool_is_not_offered_in_calc():
    from src.mirai.core.registry import ToolRegistry
    from src.mirai.core.tools import register_all

    names = [t["function"]["name"]
             for t in register_all(ToolRegistry()).openai_tools("calc")]
    assert "writer_replace_paragraphs" not in names
