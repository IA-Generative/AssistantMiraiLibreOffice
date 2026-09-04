"""Mécanisme natif de MAJ (<update-information>, issue #5) + fiabilité de la
voie in-process (issue #9) : install sur le MAIN thread via ExtensionManager,
scripts cmd.exe désactivés par défaut, réconciliation post-redémarrage.

Run:  pytest tests/unit/test_native_update.py -v
"""
import importlib.util
import json
import os
import tempfile
import time
from unittest.mock import MagicMock

from tests.stubs.uno_stubs import install, make_job

install()

from src.mirai.entrypoint import MainJob

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# ── scripts/inject_update_feed.py (bake du feed au build) ────────────────

_spec = importlib.util.spec_from_file_location(
    "inject_update_feed", os.path.join(ROOT, "scripts", "inject_update_feed.py"))
inject_update_feed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inject_update_feed)

MINIMAL_DESCRIPTION = """<?xml version='1.0' encoding='UTF-8'?>
<description
  xmlns="http://openoffice.org/extensions/description/2006"
  xmlns:xlink="http://www.w3.org/1999/xlink">
    <identifier value="fr.gouv.interieur.mirai"/>
    <version value="0.0.1.0.31"/>
</description>
"""


def _write(tmpdir, name, content):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_inject_bakes_one_src_per_bootstrap_url():
    """Chaque bootstrap_url du profil donne un <src> (failover natif LO),
    avec le chemin de feed conventionnel du DM."""
    d = tempfile.mkdtemp()
    desc = _write(d, "description.xml", MINIMAL_DESCRIPTION)
    cfg = _write(d, "config.json", json.dumps({
        "enabled": True,
        "bootstrap_urls": ["https://dm-a.example/", "https://dm-b.example"],
    }))
    msg = inject_update_feed.inject(desc, cfg)
    assert "2 feed URL(s)" in msg
    out = open(desc, encoding="utf-8").read()
    assert "<update-information>" in out
    assert 'xlink:href="https://dm-a.example/catalog/mirai-libreoffice/update.xml"' in out
    assert 'xlink:href="https://dm-b.example/catalog/mirai-libreoffice/update.xml"' in out
    # ordre préservé (LibreOffice essaie les <src> dans l'ordre)
    assert out.index("dm-a.example") < out.index("dm-b.example")
    # toujours bien formé
    import xml.etree.ElementTree as ET
    ET.fromstring(out.encode("utf-8"))


def test_inject_skips_offline_profile():
    """Profil offline (enabled:false) : pas de bloc — le bouton natif répond
    simplement « aucune mise à jour »."""
    d = tempfile.mkdtemp()
    desc = _write(d, "description.xml", MINIMAL_DESCRIPTION)
    cfg = _write(d, "config.json", json.dumps({
        "enabled": False, "bootstrap_urls": ["https://dm.example"],
    }))
    msg = inject_update_feed.inject(desc, cfg)
    assert "skipped" in msg
    assert "<update-information>" not in open(desc, encoding="utf-8").read()


def test_inject_is_idempotent():
    """Un description.xml déjà équipé n'est pas modifié (double build, repack)."""
    d = tempfile.mkdtemp()
    desc = _write(d, "description.xml", MINIMAL_DESCRIPTION)
    cfg = _write(d, "config.json", json.dumps({
        "enabled": True, "bootstrap_urls": ["https://dm.example"],
    }))
    inject_update_feed.inject(desc, cfg)
    first = open(desc, encoding="utf-8").read()
    msg = inject_update_feed.inject(desc, cfg)
    assert "already present" in msg
    assert open(desc, encoding="utf-8").read() == first


def test_inject_env_override_wins(monkeypatch):
    """MIRAI_UPDATE_FEED_URL force une URL de feed unique (builds spéciaux)."""
    d = tempfile.mkdtemp()
    desc = _write(d, "description.xml", MINIMAL_DESCRIPTION)
    cfg = _write(d, "config.json", json.dumps({
        "enabled": True, "bootstrap_urls": ["https://dm.example"],
    }))
    monkeypatch.setenv("MIRAI_UPDATE_FEED_URL", "https://override.example/update.xml")
    inject_update_feed.inject(desc, cfg)
    out = open(desc, encoding="utf-8").read()
    assert 'xlink:href="https://override.example/update.xml"' in out
    assert "dm.example" not in out


# ── Install sur le MAIN thread (ExtensionManager.addExtension) ───────────
# La voie du Gestionnaire des extensions — remplace atomiquement une extension
# de même identifiant, PAS de remove-avant-add (le cycle removePackage/addPackage
# worker est ce qui laissait des entrées fantômes dans registrymodifications.xcu).

def _job_with_sync_async_callback():
    """Job dont l'AsyncCallback exécute le callback immédiatement (synchro),
    comme si le main thread était disponible tout de suite."""
    job = make_job()
    async_cb = MagicMock(name="AsyncCallback")
    async_cb.addCallback.side_effect = lambda cb, data: cb.notify(data)
    job.ctx.getServiceManager.return_value.createInstanceWithContext.return_value = async_cb
    return job, async_cb


def test_main_thread_install_uses_extension_manager_add_only():
    """addExtension(repo 'user') via le singleton theExtensionManager, sans
    removeExtension/removePackage préalable."""
    job, async_cb = _job_with_sync_async_callback()
    mgr = MagicMock(name="theExtensionManager")
    job.ctx.getValueByName.return_value = mgr

    assert job._run_install_on_main_thread("file:///x.oxt", (), None, timeout=2) is True
    async_cb.addCallback.assert_called_once()
    job.ctx.getValueByName.assert_called_with(
        "/singletons/com.sun.star.deployment.theExtensionManager")
    mgr.addExtension.assert_called_once()
    args = mgr.addExtension.call_args.args
    assert args[0] == "file:///x.oxt"
    assert args[2] == "user"
    mgr.removeExtension.assert_not_called()
    mgr.removePackage.assert_not_called()


def test_main_thread_install_times_out_to_false():
    """Main thread indisponible (callback jamais exécuté) → False sous le
    timeout, l'appelant dégrade — et le callback tardif devient no-op."""
    job = make_job()
    async_cb = MagicMock(name="AsyncCallback")   # addCallback n'exécute rien
    job.ctx.getServiceManager.return_value.createInstanceWithContext.return_value = async_cb
    mgr = MagicMock(name="theExtensionManager")
    job.ctx.getValueByName.return_value = mgr

    start = time.time()
    assert job._run_install_on_main_thread("file:///x.oxt", (), None, timeout=0.2) is False
    assert time.time() - start < 5
    # le callback livré après coup ne doit PAS installer (anti double-install)
    cb = async_cb.addCallback.call_args.args[0]
    cb.notify(None)
    mgr.addExtension.assert_not_called()


def test_main_thread_install_reports_manager_failure():
    """addExtension lève (ex. refus de policy) → False, pour dégradation."""
    job, _ = _job_with_sync_async_callback()
    mgr = MagicMock(name="theExtensionManager")
    mgr.addExtension.side_effect = RuntimeError("denied")
    job.ctx.getValueByName.return_value = mgr

    assert job._run_install_on_main_thread("file:///x.oxt", (), None, timeout=2) is False


def test_install_and_restart_prefers_main_thread_over_legacy():
    """Main thread OK → le chemin worker legacy (removePackage/addPackage,
    vecteur de corruption) n'est PAS invoqué ; LO est fermé proprement."""
    fd, path = tempfile.mkstemp(suffix=".oxt")
    os.close(fd)
    try:
        job = make_job()
        job._run_install_on_main_thread = MagicMock(return_value=True)
        job._install_oxt_inprocess = MagicMock()
        job._close_after_inprocess_update = MagicMock()

        assert job._install_and_restart_in_process(path) is True
        job._install_oxt_inprocess.assert_not_called()
        job._close_after_inprocess_update.assert_called_once()
    finally:
        os.remove(path)


def test_install_and_restart_falls_back_to_legacy_worker_path():
    """Main thread KO → dernier recours worker (comportement historique)."""
    fd, path = tempfile.mkstemp(suffix=".oxt")
    os.close(fd)
    try:
        job = make_job()
        job._run_install_on_main_thread = MagicMock(return_value=False)
        job._install_oxt_inprocess = MagicMock(return_value=True)
        job._close_after_inprocess_update = MagicMock()

        assert job._install_and_restart_in_process(path) is True
        job._install_oxt_inprocess.assert_called_once()
        job._close_after_inprocess_update.assert_called_once()
    finally:
        os.remove(path)


# ── Réconciliation post-redémarrage (rapport « installed » véridique) ────

def _job_with_state(state, current_version="0.0.1.0.31"):
    job = make_job(config_dir=tempfile.mkdtemp())
    pend = os.path.join(job._get_user_config_dir(), "pending_update")
    os.makedirs(pend, exist_ok=True)
    with open(os.path.join(pend, "update_state.json"), "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    open(os.path.join(pend, "mirai_update.oxt"), "w").close()
    job._get_extension_version = MagicMock(return_value=current_version)
    job._report_update_status = MagicMock()
    job._send_telemetry = MagicMock()
    return job, pend


def test_reconcile_reports_installed_and_purges_on_version_match():
    """Version active == target → « installed » (véridique) rapporté au DM,
    pending_update purgé, anti-boucle levée."""
    MainJob._update_launch_blocked_cls.add("0.0.1.0.31")
    job, pend = _job_with_state({
        "campaign_id": 7, "target_version": "0.0.1.0.31",
        "version_before": "0.0.1.0.30", "stage": "user_accepted",
        "ts": time.time(),
    })
    job._reconcile_update_state()

    job._report_update_status.assert_called_once_with(
        7, "installed", "0.0.1.0.30", "0.0.1.0.31")
    assert not os.path.isdir(pend), "pending_update doit être purgé"
    assert "0.0.1.0.31" not in MainJob._update_launch_blocked_cls


def test_reconcile_keeps_fresh_pending_state():
    """MAJ pas encore appliquée (version ≠ target, état récent) → no-op :
    l'état et l'OXT stagé restent en place pour le fallback manuel."""
    job, pend = _job_with_state({
        "campaign_id": 7, "target_version": "0.0.1.0.32",
        "version_before": "0.0.1.0.31", "stage": "staged",
        "ts": time.time(),
    })
    job._reconcile_update_state()

    job._report_update_status.assert_not_called()
    assert os.path.isfile(os.path.join(pend, "update_state.json"))
    assert os.path.isfile(os.path.join(pend, "mirai_update.oxt"))


def test_reconcile_purges_stale_state():
    """État périmé (> 14 jours) → purge silencieuse, aucun rapport."""
    job, pend = _job_with_state({
        "campaign_id": 7, "target_version": "0.0.1.0.32",
        "version_before": "0.0.1.0.31", "stage": "staged",
        "ts": time.time() - 15 * 24 * 3600,
    })
    job._reconcile_update_state()

    job._report_update_status.assert_not_called()
    assert not os.path.isdir(pend)


def test_reconcile_discards_corrupt_state_file():
    """update_state.json illisible → supprimé, jamais d'exception."""
    job = make_job(config_dir=tempfile.mkdtemp())
    pend = os.path.join(job._get_user_config_dir(), "pending_update")
    os.makedirs(pend, exist_ok=True)
    state_path = os.path.join(pend, "update_state.json")
    with open(state_path, "w") as fh:
        fh.write("{not json")
    job._report_update_status = MagicMock()

    job._reconcile_update_state()

    assert not os.path.isfile(state_path)
    job._report_update_status.assert_not_called()


def test_save_update_state_roundtrip():
    """_save_update_state écrit un état relisible par la réconciliation."""
    job = make_job(config_dir=tempfile.mkdtemp())
    job._get_extension_version = MagicMock(return_value="0.0.1.0.31")
    job._save_update_state(
        {"campaign_id": 3, "target_version": "0.0.1.0.32"}, "staged")

    with open(job._update_state_path(), encoding="utf-8") as fh:
        state = json.load(fh)
    assert state["campaign_id"] == 3
    assert state["target_version"] == "0.0.1.0.32"
    assert state["version_before"] == "0.0.1.0.31"
    assert state["stage"] == "staged"
    assert state["ts"] > 0
