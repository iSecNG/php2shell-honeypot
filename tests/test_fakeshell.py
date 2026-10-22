"""Fake shell emulation tests (python -m unittest discover -s tests)."""

import unittest

import helpers  # noqa: F401  # pylint: disable=unused-import  # sys.path
from honeypot.fakeshell import FakeShell, Observation


class FakeShellTest(unittest.TestCase):
    """Command emulation of the fake shell."""

    def run_cmd(self, cmd):
        """Run cmd in a fresh fake shell and return its output."""
        return FakeShell("web-prod-02", "8.3.6").run_shell(cmd, Observation())

    def test_pipelines(self):
        """Common pipelines with head, grep, cut, awk and tr work."""
        self.assertEqual(
            self.run_cmd("cat /etc/os-release | head -2"),
            'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\n',
        )
        self.assertIn("www-data", self.run_cmd("cat /etc/passwd | grep www"))
        self.assertEqual(
            self.run_cmd("cat /etc/passwd | cut -d: -f1 | head -1"), "root\n"
        )
        self.assertEqual(
            self.run_cmd("uname -a | awk '{print $3}'"), "6.8.0-45-generic\n"
        )
        self.assertEqual(self.run_cmd("echo HELLO | tr A-Z a-z"), "hello\n")

    def test_consistent_cpu_count(self):
        """nproc matches the processor count in /proc/cpuinfo."""
        self.assertEqual(
            self.run_cmd("nproc"),
            self.run_cmd("cat /proc/cpuinfo | grep -c processor"),
        )


if __name__ == "__main__":
    unittest.main()
