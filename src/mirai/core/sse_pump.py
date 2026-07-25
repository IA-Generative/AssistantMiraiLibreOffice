"""Pump SSE générique : thread réseau → queue → drain sur le thread appelant.

INVARIANT ABSOLU : run_stream() doit être appelé depuis le thread principal
UNO — c'est lui qui pompe processEventsToIdle entre deux chunks (même cadence
que l'historique stream_request). Le thread réseau ne touche jamais à l'UI.
"""

import dataclasses
import json
import queue
import threading
import urllib.error


@dataclasses.dataclass
class RawChunk:
    chunk: dict          # chunk SSE complet parsé (porte delta.tool_calls)


@dataclasses.dataclass
class StreamHttpError:
    status: int
    body: str
    headers: object


@dataclasses.dataclass
class StreamNetworkError:
    reason: str


@dataclasses.dataclass
class StreamOutcome:
    ok: bool
    error: object = None      # StreamHttpError | StreamNetworkError | None


def run_stream(shell, request, on_event, tick=None):
    """Exécute la requête streaming ; dispatch les événements sur le thread appelant.

    on_event(event) reçoit des RawChunk dans l'ordre. Les erreurs sont
    journalisées (LlmRelayError côté coquille) et retournées dans l'outcome —
    jamais levées. `tick()` est appelé ~20×/s pendant l'attente (animation).
    """
    event_queue = queue.Queue()
    _DONE = object()

    def _network_thread():
        try:
            with shell.urlopen(request, timeout=shell.request_timeout()) as response:
                for line in response:
                    if not line.strip() or not line.startswith(b"data: "):
                        continue
                    payload = line[len(b"data: "):].decode("utf-8").strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload)
                    except Exception:
                        continue
                    event_queue.put(RawChunk(chunk))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8")
            except Exception:
                body = ""
            event_queue.put(StreamHttpError(exc.code, body, exc.headers))
        except Exception as exc:
            event_queue.put(StreamNetworkError(str(exc)))
        finally:
            event_queue.put(_DONE)

    worker = threading.Thread(target=_network_thread, daemon=True)
    worker.start()

    try:
        toolkit = shell.toolkit()
    except Exception:
        toolkit = None

    outcome = StreamOutcome(ok=True)
    while True:
        try:
            item = event_queue.get(timeout=0.05)
        except queue.Empty:
            if tick is not None:
                try:
                    tick()
                except Exception:
                    pass
            if toolkit is not None:
                try:
                    toolkit.processEventsToIdle()
                except Exception:
                    pass
            continue

        if item is _DONE:
            break
        if isinstance(item, StreamHttpError):
            shell.report_llm_error(item.status, item.body, item.headers)
            shell.log(f"[sse] HTTP {item.status} body={item.body[:500]}")
            outcome = StreamOutcome(ok=False, error=item)
            continue
        if isinstance(item, StreamNetworkError):
            shell.report_llm_network_error(item.reason)
            shell.log(f"[sse] network error: {item.reason}")
            outcome = StreamOutcome(ok=False, error=item)
            continue

        try:
            on_event(item)
        except Exception as exc:
            shell.log(f"[sse] on_event error: {exc}")
        if toolkit is not None:
            try:
                toolkit.processEventsToIdle()
            except Exception:
                pass

    return outcome
