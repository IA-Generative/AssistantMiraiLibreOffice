import json
import os
import tempfile
import time
import unittest
import urllib.error

from src.mirai.security_flow import FileJsonStore, FileQueueStore, MemoryVault, SecureBootstrapFlow


class FakeSigner(object):
    def generate_keypair(self):
        return b"\x01" * 32, b"\x02" * 32

    def public_from_private(self, private_raw):
        return b"\x02" * 32

    def sign(self, private_raw, payload_bytes):
        digest = payload_bytes[:8] if payload_bytes else b"empty"
        return b"sig:" + digest


class FakeHttp(object):
    def __init__(self):
        self.calls = []
        self._rules = []

    def add(self, method, path_suffix, status=200, body=None, headers=None, use_proxy=None, exc=None):
        self._rules.append(
            {
                "method": method.upper(),
                "path": path_suffix,
                "status": status,
                "body": body,
                "headers": headers or {},
                "use_proxy": use_proxy,
                "exc": exc,
            }
        )

    def __call__(self, method, url, headers=None, body=None, timeout=10, use_proxy=False):
        method = str(method).upper()
        self.calls.append({"method": method, "url": url, "use_proxy": use_proxy, "body": body})
        for idx, rule in enumerate(self._rules):
            if rule["method"] != method:
                continue
            if not str(url).endswith(rule["path"]):
                continue
            expected_proxy = rule["use_proxy"]
            if expected_proxy is not None and bool(expected_proxy) != bool(use_proxy):
                continue
            self._rules.pop(idx)
            if rule["exc"] is not None:
                raise rule["exc"]
            payload = rule["body"]
            if isinstance(payload, (dict, list)):
                payload = json.dumps(payload).encode("utf-8")
            elif isinstance(payload, str):
                payload = payload.encode("utf-8")
            elif payload is None:
                payload = b""
            return int(rule["status"]), dict(rule["headers"]), payload
        raise urllib.error.URLError(f"no fake route for {method} {url}")


class SecurityFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.state_path = os.path.join(self.tmpdir.name, "state.json")
        self.queue_path = os.path.join(self.tmpdir.name, "queue.json")
        self.http = FakeHttp()
        self.flow = SecureBootstrapFlow(
            bootstrap_base_url="https://example.test/bootstrap",
            plugin_uuid="plugin-123",
            device_name="device-a",
            http_call=self.http,
            log_func=lambda _m: None,
            state_store=FileJsonStore(self.state_path),
            queue_store=FileQueueStore(self.queue_path),
            vault=MemoryVault(),
            signer=FakeSigner(),
            clock=lambda: time.time(),
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def _seed_identity(self):
        self.flow.ensure_identity()
        self.flow._state["enroll_id"] = "enroll-1"
        self.flow._save_state()

    def test_anonymous_enroll_sets_preauth_token(self):
        self.http.add("POST", "/bootstrap/enroll", body={"enroll_id": "enroll-1", "challenge": "hello"})
        self.http.add(
            "POST",
            "/bootstrap/enroll/confirm",
            body={"telemetry_token": "preauth-token", "expires_in": 120},
        )
        token = self.flow.enroll_anonymous()
        self.assertEqual(token, "preauth-token")
        self.assertEqual(self.flow.telemetry_kind(), "preauth")
        self.assertFalse(self.flow.rebind_required())

    def test_refresh_uses_telemetry_token_endpoint_before_enroll(self):
        self.flow.ensure_identity()
        self.http.add(
            "GET",
            "/bootstrap/telemetry/token",
            body={"telemetryKey": "preauth-from-token-endpoint", "telemetryKeyTtlSeconds": 120},
        )
        token = self.flow.ensure_telemetry_token(min_validity=30)
        self.assertEqual(token, "preauth-from-token-endpoint")
        self.assertEqual(self.flow.telemetry_kind(), "preauth")

    def test_anonymous_enroll_without_confirm_endpoint_uses_token_endpoint(self):
        self.http.add("POST", "/bootstrap/enroll", body={"ok": True})
        self.http.add(
            "GET",
            "/bootstrap/telemetry/token",
            body={"telemetryKey": "preauth-fallback-token", "telemetryKeyTtlSeconds": 120},
        )
        token = self.flow.enroll_anonymous()
        self.assertEqual(token, "preauth-fallback-token")
        self.assertEqual(self.flow.telemetry_kind(), "preauth")

    def test_proactive_refresh_when_expiring_in_less_than_30s(self):
        self._seed_identity()
        self.flow._state["telemetry"] = {
            "token": "old-token",
            "expires_at": self.flow._effective_now() + 10,
            "kind": "preauth",
        }
        self.flow._save_state()
        self.http.add(
            "POST",
            "/bootstrap/telemetry/token",
            body={"telemetry_token": "new-token", "expires_in": 300},
        )
        token = self.flow.ensure_telemetry_token(min_validity=30)
        self.assertEqual(token, "new-token")
        self.assertEqual(self.flow._state["telemetry"]["token"], "new-token")

    def test_bind_identity_replaces_preauth_with_user_token(self):
        self._seed_identity()
        self.flow._state["telemetry"] = {
            "token": "preauth-token",
            "expires_at": self.flow._effective_now() + 300,
            "kind": "preauth",
        }
        self.flow._save_state()
        self.http.add(
            "POST",
            "/bootstrap/identity/bind",
            body={"telemetry_token": "user-token", "expires_in": 600},
        )
        token = self.flow.bind_identity("access-token")
        self.assertEqual(token, "user-token")
        self.assertEqual(self.flow.telemetry_kind(), "user")

    def test_bind_identity_without_endpoint_marks_existing_token_as_user(self):
        self._seed_identity()
        self.flow._state["telemetry"] = {
            "token": "preauth-token",
            "expires_at": self.flow._effective_now() + 300,
            "kind": "preauth",
        }
        self.flow._save_state()
        self.http.add("POST", "/bootstrap/identity/bind", status=404, body={"detail": "not found"})
        token = self.flow.bind_identity("access-token")
        self.assertEqual(token, "preauth-token")
        self.assertEqual(self.flow.telemetry_kind(), "user")

    def test_queue_retry_and_ttl_purge(self):
        self._seed_identity()
        self.flow._state["bootstrap_config"] = {"config": {"telemetryEndpoint": "https://example.test/telemetry/v1/traces"}}
        self.flow._state["telemetry"] = {
            "token": "preauth-token",
            "expires_at": self.flow._effective_now() + 300,
            "kind": "preauth",
        }
        self.flow._save_state()

        self.http.add("POST", "/telemetry/v1/traces", status=503, body={"detail": "temporary"})
        self.flow.send_trace({"resourceSpans": []})
        queued = FileQueueStore(self.queue_path).read()
        self.assertEqual(len(queued), 1)

        queued.append(
            {
                "payload": {"resourceSpans": [{"expired": True}]},
                "created_at": self.flow._effective_now() - 1000,
                "expires_at": self.flow._effective_now() - 1,
                "next_attempt_at": self.flow._effective_now() - 1,
                "attempts": 0,
                "last_reason": "expired",
            }
        )
        FileQueueStore(self.queue_path).write(queued)

        self.http.add("POST", "/telemetry/v1/traces", status=200, body={})
        self.http.add("POST", "/telemetry/v1/traces", status=200, body={})
        self.flow.send_trace({"resourceSpans": [{"ok": True}]})
        queue_after = FileQueueStore(self.queue_path).read()
        self.assertEqual(queue_after, [])

    def test_401_marks_rebind_required_after_single_refresh_attempt(self):
        self._seed_identity()
        self.flow._state["bootstrap_config"] = {"config": {"telemetryEndpoint": "https://example.test/telemetry/v1/traces"}}
        self.flow._state["telemetry"] = {
            "token": "user-token",
            "expires_at": self.flow._effective_now() + 300,
            "kind": "user",
        }
        self.flow._save_state()

        self.http.add("POST", "/telemetry/v1/traces", status=401, body={"detail": "unauthorized"})
        self.http.add("POST", "/bootstrap/telemetry/token", status=401, body={"detail": "unauthorized"})
        self.flow.send_trace({"resourceSpans": [{"user_scope": True}]})
        self.assertTrue(self.flow.rebind_required())


if __name__ == "__main__":
    unittest.main()
