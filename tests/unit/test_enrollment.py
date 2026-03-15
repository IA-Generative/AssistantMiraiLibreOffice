"""
Tests for first-time enrollment logic: _needs_first_enrollment,
_enrollment_dismissed flag, trigger() enrollment interception,
and _schedule_enrollment_check deferred auto-launch.

No LibreOffice required — UNO modules are stubbed.
"""
import base64
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from tests.stubs.uno_stubs import install, make_job

install()


def _make_jwt(payload: dict) -> str:
    """Craft a minimal JWT (unsigned) for testing."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


def _write_config(config_dir, data):
    """Write a config.json into the given config directory."""
    os.makedirs(config_dir, exist_ok=True)
    path = os.path.join(config_dir, "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


class TestNeedsFirstEnrollment(unittest.TestCase):
    """Test _needs_first_enrollment() logic."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.job = make_job(config_dir=self.config_dir)

    def test_no_config_file_returns_true(self):
        """No config.json at all → needs enrollment."""
        # config_dir is empty, no config.json
        self.assertTrue(self.job._needs_first_enrollment())

    def test_enrolled_false_no_token_returns_true(self):
        """enrolled=false, no access_token → needs enrollment."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": ""})
        self.assertTrue(self.job._needs_first_enrollment())

    def test_enrolled_true_returns_false(self):
        """enrolled=true → does NOT need enrollment."""
        _write_config(self.config_dir, {"enrolled": True})
        self.assertFalse(self.job._needs_first_enrollment())

    def test_enrolled_string_true_returns_false(self):
        """enrolled='true' (string) → does NOT need enrollment."""
        _write_config(self.config_dir, {"enrolled": "true"})
        self.assertFalse(self.job._needs_first_enrollment())

    def test_not_enrolled_but_valid_token_returns_false(self):
        """enrolled=false but valid access_token → does NOT need enrollment."""
        token = _make_jwt({"exp": int(time.time()) + 3600})
        _write_config(self.config_dir, {"enrolled": False, "access_token": token})
        self.assertFalse(self.job._needs_first_enrollment())

    def test_not_enrolled_expired_token_returns_true(self):
        """enrolled=false and expired access_token → needs enrollment."""
        token = _make_jwt({"exp": int(time.time()) - 100})
        _write_config(self.config_dir, {"enrolled": False, "access_token": token})
        self.assertTrue(self.job._needs_first_enrollment())

    def test_enrolled_false_empty_token_returns_true(self):
        """enrolled=false, access_token=' ' → needs enrollment."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": "   "})
        self.assertTrue(self.job._needs_first_enrollment())


class TestEnrollmentDismissedFlag(unittest.TestCase):
    """Test _enrollment_dismissed flag behaviour."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.job = make_job(config_dir=self.config_dir)

    def test_initial_dismissed_is_false(self):
        """Flag should start as False."""
        self.assertFalse(self.job._enrollment_dismissed)

    def test_trigger_sets_dismissed_on_enrollment_cancel(self):
        """When enrollment is needed and _run_first_enrollment returns False,
        _enrollment_dismissed should become True."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": ""})
        self.assertTrue(self.job._needs_first_enrollment())

        # Mock _run_first_enrollment to simulate cancel
        with patch.object(self.job, '_run_first_enrollment', return_value=False):
            with patch.object(self.job, '_schedule_config_refresh'):
                self.job.trigger("test_action")

        self.assertTrue(self.job._enrollment_dismissed)

    def test_trigger_skips_enrollment_when_dismissed(self):
        """Once dismissed, trigger should NOT call _run_first_enrollment again."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": ""})
        self.job._enrollment_dismissed = True

        with patch.object(self.job, '_run_first_enrollment') as mock_enroll:
            with patch.object(self.job, '_schedule_config_refresh'):
                # trigger will try to get desktop component, mock that too
                self.job.trigger("test_action")

        mock_enroll.assert_not_called()

    def test_trigger_proceeds_when_enrolled(self):
        """When already enrolled, trigger should NOT call _run_first_enrollment."""
        _write_config(self.config_dir, {"enrolled": True})

        with patch.object(self.job, '_run_first_enrollment') as mock_enroll:
            with patch.object(self.job, '_schedule_config_refresh'):
                self.job.trigger("test_action")

        mock_enroll.assert_not_called()


class TestScheduleEnrollmentCheck(unittest.TestCase):
    """Test the deferred auto-launch mechanism."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.job = make_job(config_dir=self.config_dir)

    def test_timer_fires_and_calls_enrollment(self):
        """_schedule_enrollment_check should eventually call _run_first_enrollment
        when enrollment is needed."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": ""})

        with patch.object(self.job, '_run_first_enrollment', return_value=True) as mock_enroll:
            # Use a very short timer for testing
            import threading
            original_timer = threading.Timer

            captured_fn = {}

            def fast_timer(delay, fn):
                captured_fn['fn'] = fn
                t = original_timer(0.01, fn)  # Near-instant
                t.daemon = True
                return t

            with patch('threading.Timer', side_effect=fast_timer):
                self.job._schedule_enrollment_check()

            # Wait for the timer to fire
            time.sleep(0.1)
            mock_enroll.assert_called_once()

    def test_timer_skips_when_already_enrolled(self):
        """Timer should NOT call _run_first_enrollment when already enrolled."""
        _write_config(self.config_dir, {"enrolled": True})

        with patch.object(self.job, '_run_first_enrollment') as mock_enroll:
            import threading
            original_timer = threading.Timer

            def fast_timer(delay, fn):
                t = original_timer(0.01, fn)
                t.daemon = True
                return t

            with patch('threading.Timer', side_effect=fast_timer):
                self.job._schedule_enrollment_check()

            time.sleep(0.1)
            mock_enroll.assert_not_called()

    def test_timer_skips_when_dismissed(self):
        """Timer should NOT call _run_first_enrollment when dismissed."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": ""})
        self.job._enrollment_dismissed = True

        with patch.object(self.job, '_run_first_enrollment') as mock_enroll:
            import threading
            original_timer = threading.Timer

            def fast_timer(delay, fn):
                t = original_timer(0.01, fn)
                t.daemon = True
                return t

            with patch('threading.Timer', side_effect=fast_timer):
                self.job._schedule_enrollment_check()

            time.sleep(0.1)
            mock_enroll.assert_not_called()

    def test_timer_sets_dismissed_on_cancel(self):
        """When user cancels in auto-launched wizard, dismissed flag should be set."""
        _write_config(self.config_dir, {"enrolled": False, "access_token": ""})

        with patch.object(self.job, '_run_first_enrollment', return_value=False):
            import threading
            original_timer = threading.Timer

            def fast_timer(delay, fn):
                t = original_timer(0.01, fn)
                t.daemon = True
                return t

            with patch('threading.Timer', side_effect=fast_timer):
                self.job._schedule_enrollment_check()

            time.sleep(0.1)

        self.assertTrue(self.job._enrollment_dismissed)


class TestRunFirstEnrollment(unittest.TestCase):
    """Test _run_first_enrollment orchestration."""

    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.job = make_job(config_dir=self.config_dir)

    def test_returns_false_when_config_fetch_fails(self):
        """If config fetch returns None, enrollment should fail."""
        with patch.object(self.job, '_schedule_config_refresh'):
            with patch.object(self.job, '_fetch_config', return_value=None):
                result = self.job._run_first_enrollment()
        self.assertFalse(result)

    def test_returns_true_when_auth_succeeds(self):
        """Full flow: config fetch → sync keycloak → auth → success."""
        fake_config = {"config": {"keycloakIssuerUrl": "http://test"}}
        fake_token = _make_jwt({"exp": int(time.time()) + 3600})

        with patch.object(self.job, '_schedule_config_refresh'):
            with patch.object(self.job, '_fetch_config', return_value=fake_config):
                with patch.object(self.job, '_sync_keycloak_from_config'):
                    with patch.object(self.job, '_ensure_access_token', return_value=fake_token):
                        result = self.job._run_first_enrollment()
        self.assertTrue(result)

    def test_returns_false_when_auth_fails(self):
        """Config fetch OK but auth returns None → enrollment fails."""
        fake_config = {"config": {"keycloakIssuerUrl": "http://test"}}

        with patch.object(self.job, '_schedule_config_refresh'):
            with patch.object(self.job, '_fetch_config', return_value=fake_config):
                with patch.object(self.job, '_sync_keycloak_from_config'):
                    with patch.object(self.job, '_ensure_access_token', return_value=None):
                        result = self.job._run_first_enrollment()
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
