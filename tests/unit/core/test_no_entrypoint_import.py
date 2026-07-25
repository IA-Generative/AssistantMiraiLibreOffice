"""Règle d'architecture exécutable : core/ et ui/ n'importent JAMAIS entrypoint.

La façade duck-type l'objet MainJob sans import — c'est ce qui garantit que le
moteur reste testable sans UNO et que la coquille reste intouchée.
"""

import os

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_PACKAGES = [
    os.path.join(_REPO_ROOT, "src", "mirai", "core"),
    os.path.join(_REPO_ROOT, "src", "mirai", "ui"),
]


def _python_files():
    for package in _PACKAGES:
        if not os.path.isdir(package):
            continue
        for root, _dirs, files in os.walk(package):
            for name in files:
                if name.endswith(".py"):
                    yield os.path.join(root, name)


def test_core_and_ui_never_mention_entrypoint():
    offenders = []
    for path in _python_files():
        with open(path, "r", encoding="utf-8") as fh:
            if "entrypoint" in fh.read():
                offenders.append(os.path.relpath(path, _REPO_ROOT))
    assert offenders == [], (
        "Ces fichiers mentionnent 'entrypoint' — la règle d'architecture "
        f"interdit tout couplage direct : {offenders}")


def test_tools_never_import_ui():
    tools_dir = os.path.join(_REPO_ROOT, "src", "mirai", "core", "tools")
    offenders = []
    for root, _dirs, files in os.walk(tools_dir):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
            if "from ..ui" in content or "mirai.ui" in content:
                offenders.append(os.path.relpath(path, _REPO_ROOT))
    assert offenders == []
