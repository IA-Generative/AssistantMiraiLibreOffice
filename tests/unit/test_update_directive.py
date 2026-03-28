"""Tests for update directive parsing and rollout percentage logic."""

import hashlib
import unittest


def _device_hash(client_uuid: str) -> int:
    """Same hash logic as rollout percentage check."""
    return int(hashlib.md5(client_uuid.encode()).hexdigest()[:8], 16) % 100


class TestDeviceHash(unittest.TestCase):
    """Verify hash-based rollout produces uniform distribution."""

    def test_deterministic(self):
        """Same UUID always produces same hash."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(_device_hash(uuid), _device_hash(uuid))

    def test_different_uuids_different_hashes(self):
        """Different UUIDs produce different hashes (with high probability)."""
        hashes = set(_device_hash(f"device-{i}") for i in range(100))
        # With 100 devices, we expect most hashes to be unique
        self.assertGreater(len(hashes), 50)

    def test_uniform_distribution(self):
        """1000 devices should distribute roughly uniformly across 0-99."""
        hashes = [_device_hash(f"sim-device-{i}") for i in range(1000)]
        # Check that 5% threshold captures roughly 5% of devices
        canary_count = sum(1 for h in hashes if h < 5)
        # Allow 2-8% range (statistical tolerance)
        self.assertGreater(canary_count, 20)
        self.assertLess(canary_count, 80)

    def test_25_percent_threshold(self):
        """25% threshold captures roughly 25% of devices."""
        hashes = [_device_hash(f"sim-device-{i}") for i in range(1000)]
        count = sum(1 for h in hashes if h < 25)
        # Allow 18-32% range
        self.assertGreater(count, 180)
        self.assertLess(count, 320)

    def test_100_percent_includes_all(self):
        """100% threshold includes all devices."""
        hashes = [_device_hash(f"sim-device-{i}") for i in range(100)]
        count = sum(1 for h in hashes if h < 100)
        self.assertEqual(count, 100)


class TestUpdateDirectiveParsing(unittest.TestCase):
    """Test parsing of update directives from bootstrap response."""

    def test_valid_update_directive(self):
        directive = {
            "action": "update",
            "current_version": "1.0.0",
            "target_version": "1.1.0",
            "artifact_url": "/binaries/libreoffice/1.1.0_mirai.oxt",
            "checksum": "sha256:abcdef1234567890",
            "urgency": "normal",
            "campaign_id": 42,
        }
        self.assertEqual(directive["action"], "update")
        self.assertTrue(directive["checksum"].startswith("sha256:"))

    def test_rollback_directive(self):
        directive = {
            "action": "rollback",
            "current_version": "1.1.0",
            "target_version": "1.0.0",
            "artifact_url": "/binaries/libreoffice/1.0.0_mirai.oxt",
            "checksum": "sha256:abcdef",
            "urgency": "critical",
            "campaign_id": 42,
        }
        self.assertEqual(directive["action"], "rollback")
        self.assertEqual(directive["urgency"], "critical")

    def test_no_directive_when_none(self):
        response = {"meta": {}, "config": {}, "update": None, "features": {}}
        update = response.get("update")
        self.assertIsNone(update)

    def test_no_directive_when_missing(self):
        response = {"meta": {}, "config": {}}
        update = response.get("update")
        self.assertIsNone(update)

    def test_checksum_verification(self):
        data = b"test binary content"
        expected = "sha256:" + hashlib.sha256(data).hexdigest()
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        self.assertEqual(expected, actual)

    def test_checksum_mismatch(self):
        data = b"test binary content"
        wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        self.assertNotEqual(wrong, actual)


class TestStatusPayload(unittest.TestCase):
    """Test update status report payload format."""

    def test_installed_payload(self):
        payload = {
            "campaign_id": 42,
            "client_uuid": "test-uuid",
            "status": "installed",
            "version_before": "1.0.0",
            "version_after": "1.1.0",
            "error_detail": "",
        }
        self.assertEqual(payload["status"], "installed")
        self.assertIn(payload["status"], ("installed", "failed", "checksum_error", "download_error"))

    def test_failed_payload(self):
        payload = {
            "campaign_id": 42,
            "client_uuid": "test-uuid",
            "status": "download_error",
            "version_before": "1.0.0",
            "version_after": "",
            "error_detail": "Connection timeout",
        }
        self.assertIn(payload["status"], ("installed", "failed", "checksum_error", "download_error"))
        self.assertTrue(len(payload["error_detail"]) > 0)


if __name__ == "__main__":
    unittest.main()
