"""MainThreadDispatcher : marshalling vers le thread principal.

Ces tests tournent hors LibreOffice. Le service AsyncCallback est simulé par un
faux qui garde les tâches en file et ne les exécute que lorsqu'on le lui demande
— ce qui permet de vérifier l'asynchronisme réel de `post()` et le timeout de
`call()` sans dépendre du minutage.
"""

import threading

import pytest

from src.mirai.core.ui_thread import (
    DirectDispatcher,
    DispatcherClosed,
    DispatcherTimeout,
    MainThreadDispatcher,
    is_main_thread,
)


class FakeAsyncCallback:
    """Imite com.sun.star.awt.AsyncCallback : accumule, exécute sur demande."""

    def __init__(self):
        self.queued = []

    def addCallback(self, task, _data):
        self.queued.append(task)

    def drain(self):
        """Joue les tâches en attente — ce que ferait la boucle d'événements."""
        pending, self.queued = self.queued, []
        for task in pending:
            task.run()


class FakeUnoContext:
    def __init__(self, callback=None, fail=False):
        self._callback = callback
        self._fail = fail

    def getServiceManager(self):
        return self

    def createInstanceWithContext(self, name, _ctx):
        assert name == "com.sun.star.awt.AsyncCallback"
        if self._fail:
            raise RuntimeError("service indisponible")
        return self._callback


def _dispatcher(fail=False):
    callback = FakeAsyncCallback()
    return MainThreadDispatcher(FakeUnoContext(callback, fail=fail)), callback


# ── post() ──────────────────────────────────────────────────────────────

def test_post_ne_sexecute_pas_avant_le_drain():
    dispatcher, callback = _dispatcher()
    seen = []

    assert dispatcher.post(lambda: seen.append("fait")) is True
    assert seen == [], "post() ne doit pas exécuter dans le thread appelant"

    callback.drain()
    assert seen == ["fait"]


def test_post_avale_les_exceptions():
    dispatcher, callback = _dispatcher()

    def boom():
        raise ValueError("panne d'affichage")

    dispatcher.post(boom)
    callback.drain()  # ne doit pas propager : une mise à jour d'UI ratée n'est pas fatale


def test_post_devient_inerte_apres_close():
    dispatcher, callback = _dispatcher()
    seen = []

    dispatcher.close()
    assert dispatcher.post(lambda: seen.append("fait")) is False
    callback.drain()
    assert seen == [], "après close(), plus rien ne doit s'exécuter"


def test_post_sans_asynccallback_execute_directement():
    """Dégradation gracieuse : service absent → exécution directe."""
    dispatcher, _ = _dispatcher(fail=True)
    seen = []

    assert dispatcher.post(lambda: seen.append("fait")) is True
    assert seen == ["fait"]


# ── call() ──────────────────────────────────────────────────────────────

def test_call_rapporte_le_resultat():
    dispatcher, callback = _dispatcher()
    result = {}

    def worker():
        result["value"] = dispatcher.call(lambda: 6 * 7, timeout=5)

    thread = threading.Thread(target=worker)
    thread.start()
    _drain_until(callback, thread)
    thread.join(timeout=5)

    assert result["value"] == 42


def test_call_propage_lexception_de_fn():
    dispatcher, callback = _dispatcher()
    captured = {}

    def worker():
        try:
            dispatcher.call(_raise_key_error, timeout=5)
        except KeyError as exc:
            captured["exc"] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    _drain_until(callback, thread)
    thread.join(timeout=5)

    assert isinstance(captured.get("exc"), KeyError)


def test_call_leve_timeout_si_le_thread_principal_ne_repond_pas():
    """Thread principal retenu par une modale : on abandonne, on ne gèle pas."""
    dispatcher, _callback = _dispatcher()

    with pytest.raises(DispatcherTimeout):
        dispatcher.call(lambda: "jamais atteint", timeout=0.15)


def test_call_leve_closed_apres_fermeture():
    dispatcher, _ = _dispatcher()
    dispatcher.close()

    with pytest.raises(DispatcherClosed):
        dispatcher.call(lambda: 1, timeout=1)


def test_call_ne_retient_pas_les_taches_terminees():
    """Sans purge, les tâches s'accumuleraient pour toute la vie de la palette."""
    dispatcher, callback = _dispatcher()

    def worker():
        dispatcher.call(lambda: 1, timeout=5)

    thread = threading.Thread(target=worker)
    thread.start()
    _drain_until(callback, thread)
    thread.join(timeout=5)

    assert dispatcher._pending == []


# ── DirectDispatcher (le FakeDispatcher des tests) ──────────────────────

def test_direct_dispatcher_est_synchrone():
    dispatcher = DirectDispatcher()
    seen = []

    dispatcher.post(lambda: seen.append("post"))
    assert dispatcher.call(lambda: "call") == "call"
    assert seen == ["post"]


def test_direct_dispatcher_respecte_close():
    dispatcher = DirectDispatcher()
    dispatcher.close()

    assert dispatcher.post(lambda: None) is False
    with pytest.raises(DispatcherClosed):
        dispatcher.call(lambda: None)


def test_is_main_thread():
    assert is_main_thread() is True

    seen = {}
    thread = threading.Thread(target=lambda: seen.update(value=is_main_thread()))
    thread.start()
    thread.join(timeout=5)
    assert seen["value"] is False


# ── utilitaires ─────────────────────────────────────────────────────────

def _raise_key_error():
    raise KeyError("absent")


def _drain_until(callback, thread, attempts=200):
    """Joue le rôle de la boucle d'événements pendant que le worker attend."""
    for _ in range(attempts):
        if callback.queued:
            callback.drain()
            return
        if not thread.is_alive():
            return
        threading.Event().wait(0.01)
