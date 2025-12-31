import json
import subprocess
import unittest
from unittest.mock import patch

from console.networkmanager import read_profile
from radio_audit.profile import audit_profile
from radio_audit.report import AuditError

PROFILE_UUID = "2ad46d22-0114-4e14-b1a9-123456789abc"
SETTINGS = {
    "key-mgmt": "sae",
    "pmf": "3 (required)",
    "proto": "rsn",
    "pairwise": "ccmp",
    "group": "gcmp",
}


class ProfileTests(unittest.TestCase):
    def test_saved_akm_and_rsn_do_not_prove_a_negotiated_generation(self):
        for mode, protocols, expected, verdict in [
            ("sae", "rsn", "wpa3_only", "pass"),
            ("wpa-eap-suite-b-192", "rsn", "wpa3_only", "unknown"),
            ("wpa-psk", "rsn", "wpa2_or_wpa3", "pass"),
            ("wpa-eap", "rsn", "wpa2_or_wpa3", "unknown"),
            ("wpa-psk", "wpa, rsn", "not_pinned", "fail"),
            ("wpa-psk", "wpa", "legacy_wpa_only", "fail"),
            ("sae", "wpa", "inconsistent", "fail"),
            ("wpa-psk", "", "not_pinned", "unknown"),
        ]:
            with self.subTest(mode=mode, protocols=protocols):
                report = audit_profile({**SETTINGS, "key-mgmt": mode, "proto": protocols})
                self.assertEqual(
                    report.as_dict()["evidence"],
                    {
                        "configured_generation": expected,
                        "negotiated_generation": "not_observed",
                    },
                )
                self.assertEqual(report.result, verdict)

    def test_authentication_modes_have_distinct_results(self):
        for mode, expected in [
            ("sae", "pass"),
            ("wpa-psk", "pass"),
            ("owe", "fail"),
            ("none", "fail"),
            ("ieee8021x", "fail"),
            ("wpa-eap", "unknown"),
            ("wpa-eap-suite-b-192", "unknown"),
            ("future-mode", "unknown"),
            ("", "unknown"),
        ]:
            with self.subTest(mode=mode):
                report = audit_profile({**SETTINGS, "key-mgmt": mode})
                self.assertEqual(report.result, expected)
                self.assertEqual(report.scope, "networkmanager.saved_profile")
        self.assertEqual(audit_profile({}).result, "fail")

    def test_pmf_inheritance_and_optional_are_inconclusive(self):
        for setting, expected in [
            ("0 (default)", "unknown"),
            ("default", "unknown"),
            ("", "unknown"),
            ("1 (disable)", "fail"),
            ("disable", "fail"),
            ("2 (optional)", "unknown"),
            ("required", "pass"),
            ("3", "pass"),
            ("9 (future)", "unknown"),
        ]:
            with self.subTest(pmf=setting):
                self.assertEqual(audit_profile({**SETTINGS, "pmf": setting}).result, expected)

    def test_legacy_allowed_even_alongside_modern_values_is_flagged(self):
        for field, setting, expected in [
            ("proto", "rsn, wpa", "fail"),
            ("proto", "future", "unknown"),
            ("pairwise", "ccmp tkip", "fail"),
            ("group", "wep104", "fail"),
            ("pairwise", "", "unknown"),
            ("pairwise", "ccmp,gcmp-256", "pass"),
            ("group", "DO_NOT_LOG_THIS", "unknown"),
        ]:
            with self.subTest(field=field, setting=setting):
                report = audit_profile({**SETTINGS, field: setting})
                self.assertEqual(report.result, expected)
                self.assertNotIn("DO_NOT_LOG_THIS", json.dumps(report.as_dict()))


class NetworkManagerTests(unittest.TestCase):
    def device_lines(self, identifier=PROFILE_UUID, kind="wifi"):
        return f"GENERAL.TYPE:{kind}\nGENERAL.CON-UUID:{identifier}\n"

    def profile_lines(self, settings=None, kind="802-11-wireless"):
        text = f"connection.type:{kind}\nconnection.uuid:{PROFILE_UUID}\n"
        for name, value in (SETTINGS if settings is None else settings).items():
            text += f"802-11-wireless-security.{name}:{value}\n"
        return text

    @patch("console.networkmanager.subprocess.run")
    def test_read_only_profile_fields_and_connection_change_guard(self, run):
        profile = self.profile_lines() + "802-11-wireless.ssid:DO_NOT_LOG_THIS\n"
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=text)
            for text in (self.device_lines(), profile, self.device_lines())
        ]
        result = read_profile(device="wlan0", profile_uuid=None)
        self.assertEqual(result, SETTINGS)
        args = [call.args[0] for call in run.call_args_list]
        self.assertEqual(args[0][-3:], ["device", "show", "wlan0"])
        self.assertEqual(args[1][-4:], ["connection", "show", "uuid", PROFILE_UUID])
        self.assertEqual(args[0], args[2])
        fields = args[1][args[1].index("--fields") + 1].split(",")
        self.assertEqual(
            set(fields),
            {"connection.uuid", "connection.type"}
            | {"802-11-wireless-security." + name for name in SETTINGS},
        )
        for call in run.call_args_list:
            self.assertNotIn("--show-secrets", call.args[0])
            self.assertFalse(call.kwargs.get("shell", False))

    @patch("console.networkmanager.subprocess.run")
    def test_open_saved_profile_has_no_wireless_security_section(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout=self.profile_lines({}))
        settings = read_profile(profile_uuid=PROFILE_UUID, device=None)
        self.assertEqual(audit_profile(settings).result, "fail")

    @patch("console.networkmanager.subprocess.run")
    def test_error_if_device_roams_to_another_profile_during_read(self, run):
        new_uuid = "44391986-d601-45dd-ad27-123456789abc"
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=text)
            for text in (self.device_lines(), self.profile_lines(), self.device_lines(new_uuid))
        ]
        with self.assertRaisesRegex(AuditError, "연결이 바뀌"):
            read_profile(profile_uuid=None, device="wlan0")

    @patch("console.networkmanager.subprocess.run")
    def test_disconnected_device_wrong_type_and_missing_nmcli(self, run):
        for text in (self.device_lines(""), self.device_lines(kind="ethernet")):
            run.return_value = subprocess.CompletedProcess([], 0, stdout=text)
            with self.subTest(text=text), self.assertRaises(AuditError):
                read_profile(profile_uuid=None, device="wlan0")
        for error in (
            FileNotFoundError(),
            subprocess.TimeoutExpired("nmcli", 6),
            subprocess.CalledProcessError(10, "nmcli", stderr="DO_NOT_LOG_THIS"),
        ):
            run.side_effect = error
            with self.subTest(error=type(error)), self.assertRaises(AuditError) as caught:
                read_profile(profile_uuid=PROFILE_UUID, device=None)
            self.assertNotIn("DO_NOT_LOG_THIS", str(caught.exception))

    @patch("console.networkmanager.subprocess.run")
    def test_untrusted_options_and_malformed_replies(self, run):
        for selectors in (
            {"device": "--show-secrets", "profile_uuid": None},
            {"device": None, "profile_uuid": "not a uuid"},
        ):
            with self.subTest(selectors=selectors), self.assertRaises(AuditError):
                read_profile(**selectors)
        run.assert_not_called()
        for text in (
            "",
            self.profile_lines(kind="vpn"),
            self.profile_lines().replace(PROFILE_UUID, "another"),
        ):
            run.return_value = subprocess.CompletedProcess([], 0, stdout=text)
            with self.subTest(text=text), self.assertRaises(AuditError):
                read_profile(profile_uuid=PROFILE_UUID, device=None)
