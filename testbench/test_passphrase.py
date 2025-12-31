import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from radio_audit.passphrase import audit_passphrase
from radio_audit.report import AuditError


def status_for(report, rule):
    return next(check.status for check in report.checks if check.id == rule)


class PassphraseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.blocklist = Path(directory.name) / "digests"
        self.blocklist.write_text("0" * 64 + "\n", encoding="ascii")

    def test_wpa_psk_format_boundaries(self):
        for value, expected in [
            ("", "fail"),
            ("x" * 7, "fail"),
            ("aB3!aB3!", "pass"),
            ("x" * 63, "pass"),
            ("g" * 64, "fail"),
            ("a" * 65, "fail"),
            (" ab c d ", "pass"),
            ("ab\x1fdefgh", "fail"),
            ("abc\x7fefgh", "fail"),
            ("한글입력값테스트예시", "fail"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(
                    status_for(audit_passphrase(value, "wpa-psk"), "credential.format"), expected
                )

    def test_raw_psk_requires_provenance_and_handles_hex_case(self):
        raw_key = bytes(range(32)).hex()
        report = audit_passphrase(raw_key, "wpa-psk")
        self.assertEqual(report.result, "unknown")
        self.assertEqual(status_for(report, "credential.key_origin"), "unknown")
        self.assertEqual(audit_passphrase("Aaaa" * 16, "wpa-psk").result, "fail")
        self.assertNotIn(raw_key, json.dumps(report.as_dict()))

    def test_sae_accepts_unicode_and_does_not_treat_hex_as_a_raw_key(self):
        for value in (
            "가",
            "첫 입력 문자열을 점검하는 테스트 문장",
            "size safe " * 12,
            bytes(range(32)).hex(),
        ):
            with self.subTest(value=value):
                report = audit_passphrase(value, "sae", self.blocklist)
                self.assertEqual(status_for(report, "credential.format"), "pass")
                self.assertNotIn("credential.key_origin", {c.id for c in report.checks})
        for value in ("", "a\x00b", "a\nb", "a\rb"):
            with self.subTest(invalid=value):
                self.assertEqual(audit_passphrase(value, "sae").result, "fail")

    def test_format_and_policy_are_independent(self):
        report = audit_passphrase("Abc-48 X", "wpa-psk")
        self.assertEqual(status_for(report, "credential.format"), "pass")
        self.assertEqual(status_for(report, "credential.length"), "fail")
        for value in ("z" * 18, "aA" * 10, "Ab2" * 6, "q7~Z" * 4):
            with self.subTest(value=value):
                report = audit_passphrase(value, "wpa-psk", self.blocklist)
                self.assertEqual(status_for(report, "credential.repetition"), "fail")
                self.assertEqual(report.result, "fail")

    def test_optional_blocklist_does_not_silently_pass(self):
        value = "a synthetic sample phrase"
        self.assertEqual(audit_passphrase(value, "wpa-psk").result, "unknown")
        self.assertEqual(audit_passphrase(value, "wpa-psk", self.blocklist).result, "pass")

    def test_blocklist_matches_exact_bytes_and_never_discloses_them(self):
        value = " Test용으로 적은 서로 다른 네 단어 "
        digest = hashlib.sha256(value.encode()).hexdigest()
        self.blocklist.write_bytes(digest.upper().encode() + b"\r\n")
        report = audit_passphrase(value, "sae", self.blocklist)
        self.assertEqual(status_for(report, "credential.blocklist"), "fail")
        self.assertEqual(report.result, "fail")
        self.assertEqual(audit_passphrase(value.strip(), "sae", self.blocklist).result, "pass")
        payload = json.dumps(report.as_dict(), ensure_ascii=False)
        self.assertNotIn(value, payload)
        self.assertNotIn(digest, payload.lower())

    def test_invalid_blocklist_is_an_error_even_after_a_match(self):
        value = "deliberately synthetic input"
        digest = hashlib.sha256(value.encode()).hexdigest()
        for contents in (b"", b"\n", b"A" * 65, (digest + "\nprivate bad row").encode()):
            self.blocklist.write_bytes(contents)
            with self.subTest(contents=contents), self.assertRaises(AuditError) as caught:
                audit_passphrase(value, "wpa-psk", self.blocklist)
            self.assertNotIn("private bad row", str(caught.exception))
        self.blocklist.unlink()
        with self.assertRaises(AuditError):
            audit_passphrase(value, "wpa-psk", self.blocklist)
