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


def test_report_update_status_sends_relay_headers():
    """/update/status exige des relay-creds (DM VULN-007) : le POST doit porter
    X-Relay-Client / X-Relay-Key, sinon 401 (bug observé sur log MI)."""
    job = make_job()
    job._active_bootstrap_url = MagicMock(return_value="https://dm")
    job._ensure_plugin_uuid = MagicMock(return_value="uuid-1")
    job._get_config_from_file = MagicMock(return_value="")   # pas d'access_token
    job.get_ssl_context = MagicMock(return_value=None)
    job._relay_headers = MagicMock(return_value={"X-Relay-Client": "rc_x", "X-Relay-Key": "k"})

    captured = {}

    def _fake_urlopen(req, **kw):
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        resp = MagicMock()
        resp.read.return_value = b"{}"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    job._urlopen = _fake_urlopen
    job._report_update_status(1, "installed", "0.0.1.0.13", "0.0.1.0.14")

    assert "x-relay-client" in captured["headers"]
    assert "x-relay-key" in captured["headers"]


# ── Option B : install in-process (fallback géré par l'appelant) ─────

def test_in_process_install_guard_rejects_bad_path():
    """Chemin vide / inexistant → False sans toucher UNO ni le restart."""
    job = make_job()
    job._terminate_on_main_thread = MagicMock()  # sécurité (ne pas SIGTERM le test)
    assert job._install_and_restart_in_process("") is False
    assert job._install_and_restart_in_process("/nope/does-not-exist.oxt") is False
    job._terminate_on_main_thread.assert_not_called()


def test_in_process_install_degrades_gracefully(tmp_path):
    """Fichier réel mais service de déploiement absent → False, aucun restart
    (l'appelant retombera sur le script puis le message manuel)."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".oxt")
    os.close(fd)
    try:
        job = make_job()
        job._terminate_on_main_thread = MagicMock()  # sécurité
        job.ctx.getServiceManager.return_value.createInstanceWithContext.return_value = None
        assert job._install_and_restart_in_process(path) is False
        job._terminate_on_main_thread.assert_not_called()
    finally:
        os.remove(path)
