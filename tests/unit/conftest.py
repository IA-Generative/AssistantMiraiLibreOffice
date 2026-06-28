"""Fixtures partagées pour les tests unitaires.

`MainJob` porte des drapeaux de CLASSE volontairement partagés entre instances
(`_update_in_progress_cls`, `_enrollment_dismissed_cls` — cf. « share
enrollment/update flags across instances »). Sans réinitialisation, l'état
fuit d'un test à l'autre et provoque des échecs dépendants de l'ordre.

Ce conftest réinitialise ces drapeaux avant ET après chaque test, et nettoie
en filet de sécurité d'éventuels dossiers-fantômes laissés par des chemins de
config mockés.
"""
import glob
import os
import shutil

import pytest

# Racine du repo (deux niveaux au-dessus de tests/unit/).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _reset_mainjob_flags():
    try:
        from tests.stubs.uno_stubs import install
        install()
        from src.mirai.entrypoint import MainJob
    except Exception:
        return
    MainJob._update_in_progress_cls = False
    MainJob._enrollment_dismissed_cls = False


def _cleanup_phantom_dirs():
    # Dossiers nommés d'après un repr de MagicMock (chemin de config mocké).
    for path in glob.glob(os.path.join(_REPO_ROOT, "*MagicMock*")):
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(autouse=True)
def _isolate_mainjob_state():
    _reset_mainjob_flags()
    yield
    _reset_mainjob_flags()
    _cleanup_phantom_dirs()
