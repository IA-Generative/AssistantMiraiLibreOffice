"""Contexte d'exécution des tools : document, contrôleur, undo.

Un seul contexte undo par run d'orchestrateur (ouvert paresseusement par le
premier tool mutant, fermé dans le finally du run) → l'action complète
s'annule en un seul Ctrl+Z, comme les fonctions historiques.
"""


class ToolContext:
    def __init__(self, uno_ctx, model, controller, app, shell):
        self.uno_ctx = uno_ctx
        self.model = model            # document UNO (Writer ou Calc)
        self.controller = controller  # model.CurrentController
        self.app = app                # "writer" | "calc"
        self.shell = shell            # ShellServices
        self._undo_manager = None
        self._undo_open = False

    def undo_begin(self, label):
        if self._undo_open:
            return
        try:
            self._undo_manager = self.model.getUndoManager()
            self._undo_manager.enterUndoContext(label)
            self._undo_open = True
        except Exception:
            self._undo_manager = None

    def undo_end(self):
        if not self._undo_open or self._undo_manager is None:
            self._undo_open = False
            return
        try:
            self._undo_manager.leaveUndoContext()
        except Exception:
            pass
        self._undo_open = False
