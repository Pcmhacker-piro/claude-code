#!/usr/bin/env python3
"""
Unit tests for sensitive_file_protection_example.py
"""

import sys
from pathlib import Path
import unittest

# Ensure the hook script can be imported regardless of execution working directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sensitive_file_protection_example import (
    _is_protected_path,
    _validate_tool_call,
)


class TestSensitiveFileProtection(unittest.TestCase):

    def test_protected_env_files(self):
        self.assertTrue(_is_protected_path(".env"))
        self.assertTrue(_is_protected_path("backend/.env"))
        self.assertTrue(_is_protected_path(".env.local"))
        self.assertTrue(_is_protected_path(".env.production"))

    def test_allowed_env_example_files(self):
        self.assertFalse(_is_protected_path(".env.example"))
        self.assertFalse(_is_protected_path(".env.sample"))
        self.assertFalse(_is_protected_path("config/.env.template"))

    def test_protected_credentials(self):
        self.assertTrue(_is_protected_path(".aws/credentials"))
        self.assertTrue(_is_protected_path("/home/user/.ssh/id_rsa"))
        self.assertTrue(_is_protected_path("certs/server.pem"))
        self.assertTrue(_is_protected_path("secrets/private.key"))

    def test_allowed_general_files(self):
        self.assertFalse(_is_protected_path("src/index.ts"))
        self.assertFalse(_is_protected_path("package.json"))
        self.assertFalse(_is_protected_path("README.md"))

    def test_validate_tool_call_edit_blocked(self):
        issues = _validate_tool_call("Edit", {"file_path": ".env"})
        self.assertEqual(len(issues), 1)
        self.assertIn("Access to protected sensitive file", issues[0])

    def test_validate_tool_call_edit_allowed(self):
        issues = _validate_tool_call("Edit", {"file_path": "src/App.tsx"})
        self.assertEqual(len(issues), 0)

    def test_validate_bash_cat_env_blocked(self):
        issues = _validate_tool_call("Bash", {"command": "cat .env"})
        self.assertEqual(len(issues), 1)

    def test_validate_bash_destructive_rm_blocked(self):
        issues = _validate_tool_call("Bash", {"command": "rm -rf /"})
        self.assertEqual(len(issues), 1)

    def test_validate_bash_normal_command_allowed(self):
        issues = _validate_tool_call("Bash", {"command": "npm run build"})
        self.assertEqual(len(issues), 0)


if __name__ == "__main__":
    unittest.main()
