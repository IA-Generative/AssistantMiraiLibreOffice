"""Dégradation propre + anti-boucle quand l'install auto de la MAJ est bloquée
par la politique du poste (WinError 5 — AppLocker / Defender ASR).

Run:  pytest tests/unit/test_update_blocked.py -v
"""
import threading
from unittest.mock import MagicMock

from tests.stubs.uno_stubs import install, make_job
install()

from src.mirai.entrypoint import MainJob


def test_schedule_update_skips_blocked_target():
    """Un target déjà marqué « bloqué » ne relance ni download ni prompt."""
    job = make_job()
    job._perform_update = MagicMock()
    MainJob._update_launch_blocked_cls.add("0.0.1.0.14")

    job._schedule_update({"action": "update", "target_version": "0.0.1.0.14"})

    job._perform_update.assert_not_called()
    assert MainJob._update_in_progress_cls is False


def test_schedule_update_runs_for_unblocked_target():
    """Un target non bloqué démarre bien le worker."""
    job = make_job()
    done = threading.Event()
    job._perform_update = lambda directive: done.set()

    job._schedule_update({"action": "update", "target_version": "0.0.2"})

    assert done.wait(2), "le worker d'update aurait dû tourner"


def test_notify_update_blocked_never_raises():
    """Le message d'échec ne doit jamais faire planter le worker (UNO best-effort)."""
    job = make_job()
    # Ne lève pas, même si le toolkit/MSG_BUTTONS n'est pas pleinement stubbé.
    assert job._notify_update_blocked("0.0.1.0.14", r"C:\x\pending_update\mirai_update.bat") is None
