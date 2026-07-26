"""Marshalling vers le thread principal UNO.

RÈGLE D'ARCHITECTURE : aucun appel UNO — document, contrôles, undo — ne doit
partir d'un thread de fond. Le run vit dans un worker ; tout ce qui touche
LibreOffice repasse par ce dispatcher.

Deux primitives, à choisir selon qu'on attend un résultat :

- `post(fn)`   : « fais ça quand tu peux », rend la main tout de suite.
                 Pour les mises à jour d'affichage, qui n'ont pas de retour.
- `call(fn)`   : exécute sur le thread principal et RAPPORTE la valeur.
                 Pour lire ou modifier le document depuis le worker.

`call()` est borné par un délai : si le thread principal est retenu (boîte de
dialogue modale), on abandonne proprement au lieu d'attendre indéfiniment.

Le transport est `com.sun.star.awt.AsyncCallback`, déjà éprouvé dans la
coquille et dans `_DeferredCall` de la palette. Quand il est indisponible
(tests hors LibreOffice, service absent), on retombe sur une exécution
directe : mieux vaut un comportement dégradé qu'une fonction morte.
"""

from __future__ import annotations

import queue
import threading

try:
    import unohelper
    from com.sun.star.awt import XCallback
except ImportError:  # hors LibreOffice (tests)
    unohelper = None
    XCallback = None


_CALLBACK_BASES = (unohelper.Base, XCallback) if XCallback is not None else ()


class _Task(*_CALLBACK_BASES):
    """Une unité de travail livrée au thread principal par AsyncCallback."""

    def __init__(self, fn, result_queue=None, on_done=None):
        self._fn = fn
        self._result_queue = result_queue
        self._on_done = on_done      # purge la référence gardée par le dispatcher

    def notify(self, _data=None):
        self.run()

    def run(self):
        """S'exécute sur le thread principal ; ne laisse jamais fuir d'exception."""
        if self._result_queue is None:
            try:
                self._fn()
            except Exception:
                pass
            finally:
                if self._on_done is not None:
                    self._on_done(self)
            return
        try:
            self._result_queue.put(("ok", self._fn()))
        except Exception as exc:
            self._result_queue.put(("error", exc))


class DispatcherClosed(RuntimeError):
    """La palette a été fermée : plus rien ne doit être exécuté."""


class DispatcherTimeout(RuntimeError):
    """Le thread principal n'a pas répondu dans le délai imparti."""


class MainThreadDispatcher:
    """Fait exécuter du code sur le thread principal UNO depuis n'importe quel thread.

    Une instance par palette ouverte. Après `close()`, `post()` devient inerte
    et `call()` lève `DispatcherClosed` — ce qui met fin proprement à un run
    encore en vol quand l'utilisateur ferme la fenêtre.
    """

    def __init__(self, uno_ctx, log=None):
        self.uno_ctx = uno_ctx
        self._log = log
        self._closed = False
        self._pending = []          # garde les _Task en vie jusqu'à leur notify
        self._callback_service = None   # créé une fois, conservé (voir _async_callback)

    # ── cycle de vie ────────────────────────────────────────────────────

    def close(self):
        """Rend le dispatcher inerte. Idempotent, appelable de n'importe où."""
        self._closed = True
        self._pending.clear()
        self._callback_service = None

    @property
    def closed(self) -> bool:
        return self._closed

    # ── primitives ──────────────────────────────────────────────────────

    def post(self, fn) -> bool:
        """Planifie fn sur le thread principal sans attendre. True si accepté."""
        if self._closed:
            return False
        task = _Task(fn, on_done=self._forget)
        callback = self._async_callback()
        if callback is None:
            # Pas d'AsyncCallback : exécution directe. Correct quand on est
            # déjà sur le thread principal, et seul repli possible sinon.
            task.run()
            return True
        self._pending.append(task)
        try:
            callback.addCallback(task, None)
            return True
        except Exception as exc:
            self._note(f"post: addCallback a échoué ({exc}) — exécution directe")
            self._forget(task)
            task.run()
            return True

    def call(self, fn, timeout: float = 30.0):
        """Exécute fn sur le thread principal et rend son résultat.

        À appeler depuis le worker. Lève DispatcherClosed si la palette est
        fermée, DispatcherTimeout au-delà du délai, et propage telle quelle
        l'exception levée par fn.
        """
        if self._closed:
            raise DispatcherClosed("palette fermée")

        callback = self._async_callback()
        if callback is None:
            return fn()

        result_queue = queue.Queue(maxsize=1)
        task = _Task(fn, result_queue)
        self._pending.append(task)
        try:
            callback.addCallback(task, None)
        except Exception as exc:
            self._note(f"call: addCallback a échoué ({exc}) — exécution directe")
            self._forget(task)
            return fn()

        try:
            status, payload = result_queue.get(timeout=timeout)
        except queue.Empty:
            self._forget(task)
            raise DispatcherTimeout(
                f"le thread principal n'a pas répondu en {timeout:g} s "
                "(boîte de dialogue modale ouverte ?)"
            ) from None
        self._forget(task)
        if status == "error":
            raise payload
        return payload

    # ── interne ─────────────────────────────────────────────────────────

    def _async_callback(self):
        """Rend le service AsyncCallback, créé une seule fois et CONSERVÉ.

        Le garder est nécessaire, pas seulement économique : un service créé
        en variable locale perd sa dernière référence dès le retour de `post()`
        et peut disparaître **avant d'avoir délivré** l'événement. Le symptôme
        est déroutant — une mise à jour d'affichage sur deux se perd, par
        exemple un bouton qui reste sur « Arrêter » après la fin du run.

        On ne teste PAS la disponibilité de l'interface XCallback : hors
        LibreOffice elle n'existe pas, mais le service peut être simulé. Le
        seul juge fiable est la création du service elle-même.
        """
        if self._callback_service is not None:
            return self._callback_service
        if self.uno_ctx is None:
            return None
        try:
            self._callback_service = (
                self.uno_ctx.getServiceManager().createInstanceWithContext(
                    "com.sun.star.awt.AsyncCallback", self.uno_ctx))
            return self._callback_service
        except Exception as exc:
            self._note(f"AsyncCallback indisponible ({exc})")
            return None

    def _forget(self, task):
        try:
            self._pending.remove(task)
        except ValueError:
            pass

    def _note(self, message):
        if self._log is not None:
            try:
                self._log(f"[ui-thread] {message}")
            except Exception:
                pass


class DirectDispatcher:
    """Dispatcher synchrone : exécute tout sur place.

    Utilisé par les tests (`FakeDispatcher` en est l'alias) et comme repli
    quand aucun contexte UNO n'est disponible. Même interface publique.
    """

    def __init__(self, log=None):
        self._log = log
        self._closed = False

    def close(self):
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def post(self, fn) -> bool:
        if self._closed:
            return False
        try:
            fn()
        except Exception:
            pass
        return True

    def call(self, fn, timeout: float = 30.0):
        if self._closed:
            raise DispatcherClosed("dispatcher fermé")
        return fn()


def is_main_thread() -> bool:
    """Vrai si l'appelant est le thread principal du processus.

    Sert aux garde-fous : une fonction qui doit rester sur le thread principal
    peut le vérifier au lieu de l'espérer.
    """
    return threading.current_thread() is threading.main_thread()
