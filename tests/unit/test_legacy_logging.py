"""Regression checks for optional legacy file logging."""

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import get_config
from app.logging_config import configure_legacy_file_logging


class LegacyLoggingTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.Logger("legacy-logging-test", level=logging.INFO)
        self.directory = tempfile.TemporaryDirectory(prefix="ubid-logging-test-")
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.close_handlers)

    def close_handlers(self):
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()

    def assert_console_only(self, environment):
        handler = logging.StreamHandler()
        self.logger.addHandler(handler)
        with patch.dict(os.environ, environment, clear=True):
            config = get_config()
        self.assertEqual(config["LOG_FILE"], "")
        with (
            patch("app.logging_config.os.makedirs", side_effect=AssertionError("unexpected directory write")),
            patch("app.logging_config.RotatingFileHandler", side_effect=AssertionError("unexpected file handler")),
        ):
            configure_legacy_file_logging(self.logger, config["LOG_FILE"])
        self.assertEqual(self.logger.handlers, [handler])

    def test_unset_log_file_preserves_console_without_filesystem_calls(self):
        self.assert_console_only({})

    def test_empty_log_file_preserves_console_without_filesystem_calls(self):
        self.assert_console_only({"LOG_FILE": ""})

    def test_explicit_absolute_path_keeps_rotation_and_writes_outside_cwd(self):
        root = Path(self.directory.name)
        destination = root / "runtime" / "app.log"
        source = root / "source"
        source.mkdir(mode=0o555)
        previous = Path.cwd()
        os.chdir(source)
        try:
            with patch.dict(os.environ, {"LOG_FILE": str(destination)}, clear=True):
                config = get_config()
            configure_legacy_file_logging(self.logger, config["LOG_FILE"])
            self.logger.info("synthetic log record")
            handler = self.logger.handlers[0]
            self.assertEqual(handler.maxBytes, 10485760)
            self.assertEqual(handler.backupCount, 10)
            self.assertEqual(handler.level, logging.INFO)
            self.assertIn("synthetic log record", destination.read_text())
            self.assertFalse((source / "logs").exists())
        finally:
            os.chdir(previous)

    def test_relative_filename_needs_no_empty_parent_directory(self):
        previous = Path.cwd()
        os.chdir(self.directory.name)
        try:
            configure_legacy_file_logging(self.logger, "app.log")
            self.logger.info("relative log record")
            self.assertIn("relative log record", Path("app.log").read_text())
        finally:
            os.chdir(previous)

    def test_relative_nested_path_remains_supported(self):
        previous = Path.cwd()
        os.chdir(self.directory.name)
        try:
            configure_legacy_file_logging(self.logger, "logs/app.log")
            self.logger.info("nested log record")
            self.assertIn("nested log record", Path("logs/app.log").read_text())
        finally:
            os.chdir(previous)

    def test_existing_file_is_appended(self):
        destination = Path(self.directory.name) / "app.log"
        destination.write_text("existing record\n")
        configure_legacy_file_logging(self.logger, str(destination))
        self.logger.info("new record")
        self.assertTrue(destination.read_text().startswith("existing record\n"))
        self.assertIn("new record", destination.read_text())

    def test_explicit_unusable_destination_raises_without_silent_fallback(self):
        with self.assertRaises(IsADirectoryError):
            configure_legacy_file_logging(self.logger, self.directory.name)
        self.assertEqual(self.logger.handlers, [])
        self.assertFalse((Path(self.directory.name) / "logs").exists())

    def test_default_logging_in_a_fresh_process_with_nonwritable_cwd(self):
        root = Path(self.directory.name)
        root.chmod(0o755)
        source = root / "source"
        source.mkdir(mode=0o755)
        repository = Path(__file__).resolve().parents[2]
        for name in ("config.py", "logging_config.py"):
            shutil.copyfile(repository / "app" / name, source / name)
            (source / name).chmod(0o444)
        source.chmod(0o555)
        program = """
import logging, os, runpy, sys
config = runpy.run_path(os.path.join(sys.argv[1], 'config.py'))['get_config']()
configure = runpy.run_path(os.path.join(sys.argv[1], 'logging_config.py'))['configure_legacy_file_logging']
if os.geteuid() == 0:
    os.chdir('/sys')
    assert os.statvfs('.').f_flag & os.ST_RDONLY, 'a read-only filesystem is required for the root test'
else:
    os.chdir(sys.argv[1])
    assert not os.access('.', os.W_OK), 'cwd must deny writes'
assert config['LOG_FILE'] == ''
logger = logging.Logger('readonly-cold-logging')
configure(logger, config['LOG_FILE'])
assert logger.handlers == []
"""
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", program, str(source)],
            env={},
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
