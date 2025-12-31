import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from radio_audit.auth_log import audit_auth_log
from radio_audit.report import AuditError
from testbench.test_cli import invoke

BOOT = "b" * 32
STATION = "02:ba:dc:af:00:01"
MARKER = "AP-STA-POSSIBLE-PSK-MISMATCH"


def event(n, at, *, boot=BOOT, interface="wlan0", station=STATION):
    return {
        "_COMM": "hostapd",
        "_BOOT_ID": boot,
        "__CURSOR": f"synthetic-cursor-{n}",
        "__MONOTONIC_TIMESTAMP": str(at),
        "__REALTIME_TIMESTAMP": str(1_700_000_000_000_000 + at),
        "MESSAGE": f"{interface}: {MARKER} {station}",
    }


def encode(*rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


def audit(*rows, min_events=3):
    return audit_auth_log(io.BytesIO(encode(*rows)), min_events=min_events)


class AuthLogTests(unittest.TestCase):
    def test_sliding_window_is_inclusive_and_independent_of_wall_clock_and_order(self):
        events = [event(1, 59_000_000), event(2, 61_000_000), event(3, 119_000_000)]
        events[-1]["__REALTIME_TIMESTAMP"] = "120000000"
        a = audit(*events, events[0])
        b = audit(events[2], events[0], events[0], events[1])
        self.assertEqual(a, b)
        self.assertEqual(a.result, "fail")
        self.assertEqual(a.evidence["peak_end_realtime_us"], 120_000_000)
        self.assertEqual(a.evidence["duplicate_records"], 1)
        self.assertEqual(a.evidence["unique_signals"], 3)
        self.assertEqual(a.evidence["peak_window_signals"], 3)
        self.assertEqual(a.evidence["groups_over_threshold"], 1)
        events[-1]["__MONOTONIC_TIMESTAMP"] = "119000001"
        self.assertEqual(audit(*events).result, "pass")

    def test_no_cross_boot_radio_or_client_correlation(self):
        rows = [
            event(1, 100),
            event(2, 100, boot="c" * 32),
            event(3, 100, interface="wlan1"),
            event(4, 100, station="02:ba:dc:af:00:02"),
            event(5, 100, station=STATION.upper()),
        ]
        report = audit(*rows)
        self.assertEqual(report.result, "pass")
        self.assertEqual(report.evidence["peak_window_signals"], 2)
        self.assertEqual(report.evidence["groups_over_threshold"], 0)
        self.assertEqual(audit(*rows, min_events=2).evidence["groups_over_threshold"], 1)

    def test_no_alert_from_reimporting_one_record(self):
        first = event(1, 100)
        report = audit(*([first] * 12))
        self.assertEqual(report.result, "pass")
        self.assertEqual(report.evidence["unique_signals"], 1)
        self.assertEqual(report.evidence["duplicate_records"], 11)

    def test_other_messages_and_foreign_processes_are_not_mismatches(self):
        row = event(1, 5)
        for replacement in (
            {"MESSAGE": f"wlan0: AP-STA-DISCONNECTED {STATION}"},
            {"MESSAGE": f"diagnostic text contains {row['MESSAGE']}"},
            {"_COMM": "another-process", "SYSLOG_IDENTIFIER": "hostapd"},
        ):
            with self.subTest(replacement=replacement):
                report = audit({**row, **replacement})
                self.assertEqual(report.evidence["unique_signals"], 0)
                self.assertEqual(report.result, "unknown")
        for unit in ("hostapd.service", "hostapd@lab.service"):
            journal_row = {**row, "_SYSTEMD_UNIT": unit}
            del journal_row["_COMM"]
            self.assertEqual(audit(journal_row).evidence["unique_signals"], 1)

    def test_a_syslog_identifier_alone_cannot_establish_the_source(self):
        rows = [event(i, i) for i in range(5)]
        for row in rows:
            del row["_COMM"]
            row["SYSLOG_IDENTIFIER"] = "hostapd"
        report = audit(*rows)
        self.assertEqual(report.result, "unknown")
        self.assertEqual(report.evidence["unique_signals"], 0)
        self.assertEqual(report.evidence["unusable_records"], 5)

    def test_incomplete_evidence_cannot_clear_a_window_but_keeps_confirmed_alerts(self):
        row = event(4, 4)
        for replacement in (
            {"MESSAGE": f"{MARKER} {STATION}"},
            {"MESSAGE": None},
            {"MESSAGE": f"wlan0: {MARKER} bad"},
            {"_BOOT_ID": False},
            {"__MONOTONIC_TIMESTAMP": "-1"},
            {"__REALTIME_TIMESTAMP": "2e3"},
            {"__CURSOR": []},
        ):
            with self.subTest(replacement=replacement):
                incomplete = {**row, **replacement}
                report = audit(event(1, 1), incomplete)
                self.assertEqual(report.result, "unknown")
                self.assertEqual(report.evidence["unusable_records"], 1)
                self.assertEqual(
                    audit(event(1, 1), event(2, 2), event(3, 3), incomplete).result, "fail"
                )

    def test_malformed_input_errors_redact_rows_and_do_not_return_partial_results(self):
        prefix = encode(event(1, 1), event(2, 2))
        for suffix in (b"PRIVATE-MARKER!", b"[]", b"\xff", b"x" * (1024 * 1024 + 1)):
            with self.subTest(size=len(suffix)), self.assertRaises(AuditError) as caught:
                audit_auth_log(io.BytesIO(prefix + suffix))
            self.assertIn("3번째 줄", str(caught.exception))
            self.assertNotIn("PRIVATE-MARKER", str(caught.exception))

    def test_cli_accepts_files_and_pipes_and_redacts_journal_identifiers(self):
        data = encode(*(event(i, i) for i in range(5)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.jsonl"
            path.write_bytes(data)
            file_result = invoke("auth-log", str(path), "--json")
            piped = invoke("auth-log", "-", "--json", data=data)
        self.assertEqual(piped.returncode, 1)
        self.assertEqual(file_result.returncode, 1)
        self.assertEqual(file_result.stdout, piped.stdout)
        self.assertEqual(json.loads(piped.stdout)["evidence"]["unique_signals"], 5)
        for secret in (STATION, BOOT, "synthetic-cursor", "wlan0"):
            self.assertNotIn(secret.encode(), piped.stdout + piped.stderr)
        empty = invoke("auth-log", "-", "--json", data=b"")
        self.assertEqual(empty.returncode, 3)
        for args in (
            ["-", "--window-seconds", "0"],
            ["-", "--min-events", "1"],
            ["/missing/private-log"],
        ):
            result = invoke("auth-log", *args, "--json", data=data)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(json.loads(result.stderr)["result"], "error")
            self.assertNotIn(b"private-log", result.stderr)


def journal_writer():
    installed = shutil.which("systemd-journal-remote")
    if installed:
        return installed
    path = Path("/usr/lib/systemd/systemd-journal-remote")
    return str(path) if path.is_file() else None


@unittest.skipUnless(
    journal_writer() and shutil.which("journalctl"), "requires local systemd journal tools"
)
class NativeJournalTests(unittest.TestCase):
    def test_real_journalctl_json_round_trip(self):
        export = bytearray()
        for i in range(5):
            row = event(i, (59 + i) * 1_000_000)
            del row["__CURSOR"]
            row["_MACHINE_ID"] = "d" * 32
            export.extend("".join(f"{k}={v}\n" for k, v in row.items()).encode() + b"\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.journal"
            subprocess.run(
                [journal_writer(), f"--output={path}", "-"],
                input=export,
                check=True,
                capture_output=True,
                timeout=10,
            )
            output = subprocess.run(
                ["journalctl", f"--file={path}", "--no-pager", "--output=json"],
                check=True,
                capture_output=True,
                timeout=10,
            )
        result = invoke("auth-log", "-", "--json", data=output.stdout)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        report = json.loads(result.stdout)
        self.assertEqual(report["scope"], "hostapd.journal")
        self.assertEqual(report["evidence"]["unique_signals"], 5)
        self.assertEqual(report["evidence"]["groups_over_threshold"], 1)
