"""Diagnostic logging setup tests.

Run with: python -m unittest discover -s tests
"""

import logging
import os
import unittest
from unittest import mock

import helpers  # noqa: F401  # pylint: disable=unused-import  # sys.path
from honeypot.logsetup import parse_level, setup_logging


class LogSetupTest(unittest.TestCase):
    """HP_LOG_LEVEL parsing and root logger configuration."""

    def setUp(self):
        """Remember the root logger state so tests can't leak it."""
        root = logging.getLogger()
        self.addCleanup(root.setLevel, root.level)
        self.addCleanup(setattr, root, "handlers", root.handlers[:])

    def test_parse_level(self):
        """Names in any case and numbers work, unknown names are None."""
        self.assertEqual(parse_level(None), logging.INFO)
        self.assertEqual(parse_level(""), logging.INFO)
        self.assertEqual(parse_level(" debug "), logging.DEBUG)
        self.assertEqual(parse_level("WARNING"), logging.WARNING)
        self.assertEqual(parse_level("15"), 15)
        self.assertIsNone(parse_level("verbose"))

    def test_default_is_info(self):
        """Without HP_LOG_LEVEL the root logger is set to INFO."""
        with mock.patch.dict(os.environ):
            os.environ.pop("HP_LOG_LEVEL", None)
            setup_logging()
        self.assertEqual(logging.getLogger().level, logging.INFO)

    def test_level_from_env(self):
        """HP_LOG_LEVEL sets the root logger level."""
        with mock.patch.dict(os.environ, {"HP_LOG_LEVEL": "error"}):
            setup_logging()
        self.assertEqual(logging.getLogger().level, logging.ERROR)

    def test_invalid_level_falls_back(self):
        """An unknown level falls back to INFO and logs a warning."""
        with mock.patch.dict(os.environ, {"HP_LOG_LEVEL": "loud"}):
            with self.assertLogs("honeypot.logsetup", "WARNING") as cm:
                setup_logging()
        self.assertEqual(logging.getLogger().level, logging.INFO)
        self.assertIn("loud", cm.output[0])


if __name__ == "__main__":
    unittest.main()
