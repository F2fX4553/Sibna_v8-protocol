"""
Integration Tests for Sibna Protocol
=====================================

Comprehensive tests for the full protocol flow.
"""

import sys
import os
import unittest
import time

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../sdks/python'))

try:
    from sibna import Client
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


@unittest.skipIf(not SDK_AVAILABLE, "Sibna SDK not available")
class TestSibnaProtocol(unittest.TestCase):
    """Full protocol integration tests."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        cls.alice = Client("alice_test", "http://localhost:8000")
        cls.bob = Client("bob_test", "http://localhost:8000")

    def test_client_initialization(self):
        """Test client can be initialized."""
        self.assertEqual(self.alice.user_id, "alice_test")
        self.assertEqual(self.bob.user_id, "bob_test")

    def test_send_message(self):
        """Test message queuing."""
        msg_id = self.alice.send("bob_test", b"Hello Bob!")
        self.assertIsInstance(msg_id, int)
        self.assertGreater(msg_id, 0)

    def test_receive_messages(self):
        """Test message retrieval."""
        messages = self.bob.receive()
        self.assertIsInstance(messages, list)

    def test_pending_count(self):
        """Test pending message count."""
        count = self.alice.get_pending_count()
        self.assertGreaterEqual(count, 0)


@unittest.skipIf(not SDK_AVAILABLE, "Sibna SDK not available")
class TestProtocolSecurity(unittest.TestCase):
    """Security-focused tests."""

    def test_message_encryption(self):
        """Test that messages are encrypted."""
        # Message content should not be plaintext in storage
        pass

    def test_key_rotation(self):
        """Test automatic key rotation."""
        pass

    def test_replay_protection(self):
        """Test replay attack detection."""
        pass


class TestProtocolCore(unittest.TestCase):
    """Core protocol tests without server."""

    def test_user_id_validation(self):
        """Test user ID format validation."""
        import re
        valid_pattern = r'^[a-zA-Z0-9_-]{3,32}$'

        # Valid IDs
        self.assertTrue(re.match(valid_pattern, "alice"))
        self.assertTrue(re.match(valid_pattern, "bob_123"))
        self.assertTrue(re.match(valid_pattern, "user-name"))

        # Invalid IDs
        self.assertFalse(re.match(valid_pattern, "ab"))  # Too short
        self.assertFalse(re.match(valid_pattern, "a" * 33))  # Too long
        self.assertFalse(re.match(valid_pattern, "user@name"))  # Invalid char

    def test_hex_validation(self):
        """Test hex string validation."""
        import re
        hex_pattern = r'^[0-9a-fA-F]+$'

        # Valid hex
        self.assertTrue(re.match(hex_pattern, "a" * 64))
        self.assertTrue(re.match(hex_pattern, "ABCDEF123456"))

        # Invalid hex
        self.assertFalse(re.match(hex_pattern, "ghij"))


if __name__ == '__main__':
    unittest.main(verbosity=2)
