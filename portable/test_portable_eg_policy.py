"""Portable EG hardcode and fail-closed regression tests (safe E0 only)."""
import contextlib
import importlib.util
import io
import json
import unittest
from pathlib import Path

W = Path("/content/workspace")
spec = importlib.util.spec_from_file_location("portable_eg", W / "bin/eg-task.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class PortableEGPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            assert p.execute("hostname") == 0, "EG-managed probe rejected"
        cls.receipt = json.loads(captured.getvalue().strip())

    def test_policy_flags_are_hardcoded(self):
        for name in ("EG_REQUIRED", "REQUIRE_SIGNED_PRE",
                     "REQUIRE_VERIFIED_POST", "REQUIRE_TERMINAL_ACCEPTANCE",
                     "REQUIRE_AUTHENTICATED_AUDIT", "DENY_UNREGISTERED",
                     "DENY_UNLISTED", "NO_AUTOMATIC_RETRY_UNKNOWN_EFFECT",
                     "EFFECTS_E3_TO_E5_DENIED"):
            self.assertIs(getattr(p, name), True, name)

    def test_only_preapproved_jobs(self):
        self.assertEqual(set(p.JOBS),
                         {"hostname", "uptime", "workspace-list", "e2-smoke"})
        for name in ("bash", "/bin/sh", "../escape", "sudo", "E3"):
            with self.subTest(name=name):
                with self.assertRaises(p.Denied):
                    p.execute(name)

    def test_runtime_audit_is_authenticated(self):
        report = p.require_audit()
        self.assertEqual(report["status"], "PASS")

    def test_step_by_step_verified(self):
        task = self.receipt["task_id"]
        state = p.check_terminal(task, "hostname", "E0")
        self.assertEqual(state["contract_status"], "SATISFIED")

    def test_receipt_cannot_be_reused_for_another_job(self):
        with self.assertRaises(p.Denied):
            p.check_terminal(self.receipt["task_id"], "uptime", "E0")

    def test_nonexistent_task_is_not_accepted(self):
        with self.assertRaises(Exception):
            p.check_terminal("invalid-eg-task-does-not-exist", "hostname", "E0")

if __name__ == "__main__":
    unittest.main(verbosity=2)
