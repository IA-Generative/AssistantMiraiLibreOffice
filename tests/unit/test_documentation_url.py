"""
Tests for _open_documentation and _open_mirai_website URL-resolution logic.

No LibreOffice required — UNO modules are stubbed.
"""
import unittest
from unittest.mock import patch, MagicMock

from tests.stubs.uno_stubs import install

install()

from src.mirai.menu_actions.writer import _open_documentation, _open_mirai_website


def _make_job(config: dict) -> MagicMock:
    """Return a minimal mock job whose get_config reads from *config*."""
    job = MagicMock()
    job.get_config.side_effect = lambda key, default="": config.get(key, default)
    return job


class TestDocumentationUrl(unittest.TestCase):

    def test_doc_url_used_when_set(self):
        """When both doc_url and portal_url are set, doc_url is used."""
        job = _make_job({
            "doc_url": "https://doc.example.com",
            "portal_url": "https://portal.example.com",
        })
        with patch("webbrowser.open") as mock_open:
            _open_documentation(job)
        mock_open.assert_called_once_with("https://doc.example.com")

    def test_portal_url_fallback_when_no_doc_url(self):
        """When doc_url is empty, portal_url is used as fallback."""
        job = _make_job({
            "doc_url": "",
            "portal_url": "https://portal.example.com",
        })
        with patch("webbrowser.open") as mock_open:
            _open_documentation(job)
        mock_open.assert_called_once_with("https://portal.example.com")

    def test_no_url_does_nothing(self):
        """When both doc_url and portal_url are empty, webbrowser.open is never called."""
        job = _make_job({
            "doc_url": "",
            "portal_url": "",
        })
        with patch("webbrowser.open") as mock_open:
            _open_documentation(job)
        mock_open.assert_not_called()

    def test_portal_url_used_for_website(self):
        """_open_mirai_website opens portal_url when it is configured."""
        job = _make_job({
            "portal_url": "https://portal.example.com",
        })
        with patch("webbrowser.open") as mock_open:
            _open_mirai_website(job)
        mock_open.assert_called_once_with("https://portal.example.com")

    def test_website_fallback_to_hardcoded(self):
        """_open_mirai_website falls back to the hardcoded URL when portal_url is empty."""
        job = _make_job({
            "portal_url": "",
        })
        with patch("webbrowser.open") as mock_open:
            _open_mirai_website(job)
        mock_open.assert_called_once_with("https://mirai.interieur.gouv.fr")


if __name__ == "__main__":
    unittest.main()
