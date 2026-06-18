"""Tests for shared HTTP/proxy helpers."""

import ssl
import unittest
import urllib.request

from src.mirai.http_helpers import (
    as_bool,
    build_proxy_opener,
    normalize_proxy_url,
    split_endpoint_api_path,
)


class TestAsBool(unittest.TestCase):
    def test_string_false_is_false(self):
        self.assertFalse(as_bool("false"))

    def test_string_true_is_true(self):
        self.assertTrue(as_bool("true"))

    def test_numeric_zero_is_false(self):
        self.assertFalse(as_bool(0))


class TestEndpointHelpers(unittest.TestCase):
    def test_split_openwebui_endpoint_adds_api(self):
        self.assertEqual(
            split_endpoint_api_path("https://api.example.com", True),
            ("https://api.example.com", "/api"),
        )

    def test_split_openai_endpoint_adds_v1(self):
        self.assertEqual(
            split_endpoint_api_path("https://api.example.com", False),
            ("https://api.example.com", "/v1"),
        )

    def test_normalize_proxy_url_adds_scheme(self):
        self.assertEqual(
            normalize_proxy_url("proxy.local:8080"),
            "http://proxy.local:8080",
        )


class TestBuildProxyOpener(unittest.TestCase):
    def test_proxy_auth_keeps_auth_handlers(self):
        opener = build_proxy_opener(
            {
                "enabled": True,
                "proxy_url": "proxy.local:8080",
                "username": "alice",
                "password": "secret",
            },
            context=ssl.create_default_context(),
        )

        handler_names = [type(handler).__name__ for handler in opener.handlers]
        self.assertIn("ProxyBasicAuthHandler", handler_names)
        self.assertIn("ProxyDigestAuthHandler", handler_names)

        proxy_handler = next(
            handler for handler in opener.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        )
        self.assertEqual(
            proxy_handler.proxies["http"],
            "http://alice:secret@proxy.local:8080",
        )

    def test_disabled_proxy_does_not_register_proxy_handler(self):
        opener = build_proxy_opener({"enabled": False}, context=None)
        proxy_handlers = [
            handler for handler in opener.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(proxy_handlers, [])


if __name__ == "__main__":
    unittest.main()
