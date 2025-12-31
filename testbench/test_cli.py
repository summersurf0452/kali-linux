import hashlib
import json
import os
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from console.__main__ import MAX_INPUT_BYTES, _read_secret
from radio_audit.report import AuditError

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-B", "-m", "console"]


def invoke(*args, data=b""):
    return subprocess.run(
        [*CLI, *args],
        input=data,
        capture_output=True,
        check=False,
        cwd=ROOT,
        timeout=5,
        start_new_session=True,
    )


class CliTests(unittest.TestCase):
    def test_help_shows_entry_points_and_exit_codes(self):
        result = invoke("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("python3 -m console", result.stdout.decode())
        self.assertIn("3은 확인 불가", result.stdout.decode())

    def test_pipeline_preserves_spaces_and_never_prints_the_secret(self):
        raw = b"  sample passphrase for CLI  "
        digest = hashlib.sha256(raw).hexdigest().encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blocked"
            path.write_bytes(digest + b"\n")
            for suffix in (b"", b"\n", b"\r\n"):
                with self.subTest(suffix=suffix):
                    result = invoke(
                        "passphrase",
                        "--stdin",
                        "--json",
                        "--blocklist",
                        str(path),
                        data=raw + suffix,
                    )
                    self.assertEqual(result.returncode, 1)
                    data = json.loads(result.stdout)
                    self.assertEqual((data["schema_version"], data["result"]), (1, "fail"))
                    self.assertNotIn(raw.strip(), result.stdout + result.stderr)
                    self.assertNotIn(digest, result.stdout + result.stderr)
            passed = invoke(
                "passphrase", "--stdin", "--json", "--blocklist", str(path), data=raw.strip()
            )
            self.assertEqual(passed.returncode, 0)
            self.assertEqual(json.loads(passed.stdout)["result"], "pass")
        unknown = invoke("passphrase", "--stdin", "--json", data=raw)
        self.assertEqual(unknown.returncode, 3)
        self.assertEqual(json.loads(unknown.stdout)["result"], "unknown")

    def test_stdin_errors_have_no_partial_report_or_input_echo(self):
        marker = b"private-fixture"
        for value in (
            b"",
            marker + b"\nsecond line\n",
            marker + b"\xff",
            marker + b"x" * MAX_INPUT_BYTES,
        ):
            with self.subTest(size=len(value)):
                result = invoke("passphrase", "--stdin", "--json", data=value)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(json.loads(result.stderr)["result"], "error")
                self.assertNotIn(marker, result.stderr)

    def test_no_prompt_fallback_or_secret_command_line_argument(self):
        marker = "unexpected-private-value"
        for args in (["passphrase", marker], ["passphrase", "--mode", marker], ["passphrase"]):
            with self.subTest(args=args):
                result = invoke(*args, data=marker.encode())
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(marker.encode(), result.stdout + result.stderr)

    def test_invalid_terminal_encoding_yields_a_safe_error(self):
        with (
            patch("getpass.getpass", return_value="private-value\udcff"),
            self.assertRaises(AuditError) as caught,
        ):
            _read_secret(False)
        self.assertNotIn("private-value", str(caught.exception))

    def test_interactive_terminal_hides_input(self):
        marker = b"synthetic local tty value"
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        with subprocess.Popen(
            [*CLI, "passphrase", "--json"],
            cwd=ROOT,
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=slave,
            start_new_session=True,
        ) as process:
            try:
                screen = b""
                deadline = time.monotonic() + 4
                while b": " not in screen:
                    ready, _, _ = select.select(
                        [master], [], [], max(0, deadline - time.monotonic())
                    )
                    self.assertTrue(ready, "password prompt did not appear")
                    screen += os.read(master, 4096)
                os.write(master, marker + b"\n")
                output, _ = process.communicate(timeout=4)
                while select.select([master], [], [], 0)[0]:
                    screen += os.read(master, 4096)
                self.assertEqual(process.returncode, 3)
                self.assertEqual(json.loads(output)["result"], "unknown")
                self.assertNotIn(marker, screen + output)
            finally:
                if process.poll() is None:
                    process.kill()
