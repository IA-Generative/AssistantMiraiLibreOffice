"""Wrapper tests for dialog helper extraction."""

import unittest
from unittest.mock import patch

from tests.stubs.uno_stubs import install, make_job

install()


class TestDialogWrappers(unittest.TestCase):
    def setUp(self):
        self.job = make_job()

    @patch("src.mirai.entrypoint.show_input_box", return_value="ok")
    def test_input_box_delegates_to_helper(self, helper):
        result = self.job.input_box(
            "Bonjour",
            title="Titre",
            default="texte",
            x=10,
            y=20,
            ok_label="Valider",
            cancel_label="Fermer",
            always_on_top=True,
        )

        self.assertEqual(result, "ok")
        helper.assert_called_once()
        args, kwargs = helper.call_args
        self.assertIs(args[0], self.job)
        self.assertEqual(kwargs["message"], "Bonjour")
        self.assertEqual(kwargs["title"], "Titre")
        self.assertEqual(kwargs["default"], "texte")
        self.assertEqual(kwargs["x"], 10)
        self.assertEqual(kwargs["y"], 20)
        self.assertEqual(kwargs["ok_label"], "Valider")
        self.assertEqual(kwargs["cancel_label"], "Fermer")
        self.assertTrue(kwargs["always_on_top"])

    @patch("src.mirai.entrypoint.show_proxy_settings_box", return_value={"proxy_enabled": True})
    def test_proxy_settings_box_delegates_to_helper(self, helper):
        result = self.job.proxy_settings_box("Proxy perso", x=1, y=2)

        self.assertEqual(result, {"proxy_enabled": True})
        helper.assert_called_once()
        args, kwargs = helper.call_args
        self.assertIs(args[0], self.job)
        self.assertEqual(kwargs["title"], "Proxy perso")
        self.assertEqual(kwargs["x"], 1)
        self.assertEqual(kwargs["y"], 2)

    @patch("src.mirai.entrypoint.show_credentials_box", return_value=("alice", "secret"))
    def test_credentials_box_delegates_to_helper(self, helper):
        result = self.job.credentials_box(
            title="SSO",
            login_label="Utilisateur",
            password_label="Code",
        )

        self.assertEqual(result, ("alice", "secret"))
        helper.assert_called_once()
        args, kwargs = helper.call_args
        self.assertIs(args[0], self.job)
        self.assertEqual(kwargs["title"], "SSO")
        self.assertEqual(kwargs["login_label"], "Utilisateur")
        self.assertEqual(kwargs["password_label"], "Code")


if __name__ == "__main__":
    unittest.main()
