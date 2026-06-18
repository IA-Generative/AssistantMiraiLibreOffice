"""Tests for the HttpClient abstraction."""

import ssl
import tempfile
import unittest
import urllib.request

from src.mirai.http_client import HttpClient


class _FakeOpener:
    def __init__(self, response="ok"):
        self.response = response
        self.calls = []

    def open(self, request, timeout=None):
        self.calls.append((request, timeout))
        return self.response


class TestHttpClient(unittest.TestCase):
    def _make_client(self, config=None, proxy_cfg=None, user_dir=None):
        config = config or {}
        proxy_cfg = proxy_cfg or {
            "enabled": False,
            "proxy_url": "",
            "username": "",
            "password": "",
            "allow_insecure_ssl": False,
        }
        temp_dir = user_dir or tempfile.gettempdir()
        return HttpClient(
            config_getter=lambda key, default=None: config.get(key, default),
            proxy_config_getter=lambda: dict(proxy_cfg),
            user_config_dir_getter=lambda: temp_dir,
            relay_headers_getter=lambda: {"X-Relay-Key": "relay-secret"},
            with_user_agent=lambda headers=None: {"User-Agent": "test-agent", **(headers or {})},
            log_fn=lambda _message: None,
            base_dir=temp_dir,
        )

    def test_get_ssl_context_keeps_verification_for_string_false(self):
        client = self._make_client(config={"proxy_allow_insecure_ssl": "false"})
        ctx = client.get_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertNotEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_urlopen_adds_proxy_authorization_header(self):
        client = self._make_client(proxy_cfg={
            "enabled": True,
            "proxy_url": "proxy.local:8080",
            "username": "alice",
            "password": "secret",
            "allow_insecure_ssl": False,
        })
        opener = _FakeOpener()
        client.build_proxy_opener = lambda proxy_cfg, context=None: opener

        request = urllib.request.Request("https://example.com")
        result = client.urlopen(request, context=ssl.create_default_context(), timeout=12)

        self.assertEqual(result, "ok")
        self.assertEqual(opener.calls[0][1], 12)
        header = request.get_header("Proxy-authorization")
        self.assertIsNotNone(header)
        self.assertTrue(header.startswith("Basic "))

    def test_urlopen_injects_relay_headers_for_relay_urls(self):
        client = self._make_client()
        opener = _FakeOpener()
        client.build_proxy_opener = lambda proxy_cfg, context=None: opener

        request = urllib.request.Request("https://example.com/relay-assistant/chat")
        client.urlopen(request, context=ssl.create_default_context(), timeout=5)

        self.assertEqual(request.get_header("X-relay-key"), "relay-secret")


if __name__ == "__main__":
    unittest.main()
