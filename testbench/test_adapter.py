import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from radio_audit.adapter import audit_adapter
from radio_audit.report import AuditError
from radio_audit.rfkill import read_radio_switch
from testbench.test_cli import invoke


class AdapterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        pci = self.root / "devices" / "pci-controller"
        self.hardware = pci / "usb1" / "1-1" / "1-1:1.0"
        self.phy = self.hardware / "ieee80211" / "lab-radio"
        self.phy.mkdir(parents=True)
        (self.phy / "index").write_text("4\n")
        for node, bus, driver in ((pci, "pci", "xhci_hcd"), (self.hardware, "usb", "fixture_wifi")):
            subsystem = self.root / "bus" / bus
            bound = subsystem / "drivers" / driver
            bound.mkdir(parents=True)
            (node / "subsystem").symlink_to(subsystem)
            (node / "driver").symlink_to(bound)
        self.phy_link = self.root / "class/net/wlan0/phy80211"
        self.phy_link.parent.mkdir(parents=True)
        self.phy_link.symlink_to(self.phy)
        self.switch = self.phy / "rfkill27"
        self.switch.mkdir()
        entries = self.root / "class/rfkill"
        entries.mkdir()
        (entries / self.switch.name).symlink_to(self.switch)
        for key, value in {"type": "wlan", "hard": "0", "soft": "0"}.items():
            (self.switch / key).write_text(value + "\n")

    def test_driver_and_radio_remain_the_same_for_two_interface_names(self):
        second = self.root / "class/net/wlan1/phy80211"
        second.parent.mkdir()
        second.symlink_to(self.phy)
        report = audit_adapter("wlan0", sysfs=self.root)
        self.assertEqual(report, audit_adapter("wlan1", sysfs=self.root))
        self.assertEqual(report.result, "pass")
        self.assertEqual(
            report.evidence,
            {
                "wiphy_index": 4,
                "bus": "usb",
                "driver": "fixture_wifi",
                "soft_blocked": 0,
                "hard_blocked": 0,
            },
        )

    def test_unbound_usb_interface_does_not_borrow_the_pci_controller_driver(self):
        (self.hardware / "driver").unlink()
        report = audit_adapter("wlan0", sysfs=self.root)
        self.assertEqual(report.result, "unknown")
        self.assertNotIn("xhci_hcd", json.dumps(report.as_dict()))

    def test_software_and_hardware_blocks_are_independent_and_reasons_can_coexist(self):
        for soft, hard, flags, reason in [
            (1, 0, None, None),
            (0, 1, None, "not_reported"),
            (1, 1, "0x3", "hardware_signal+host_not_owner"),
            (0, 1, "0x6", "host_not_owner+unknown_bits"),
        ]:
            with self.subTest(soft=soft, hard=hard, flags=flags):
                (self.switch / "soft").write_text(str(soft))
                (self.switch / "hard").write_text(str(hard))
                if flags:
                    (self.switch / "hard_block_reasons").write_text(flags)
                report = audit_adapter("wlan0", sysfs=self.root)
                self.assertEqual([check.status for check in report.checks], ["pass", "fail"])
                self.assertEqual(report.evidence["soft_blocked"], soft)
                self.assertEqual(report.evidence["hard_blocked"], hard)
                self.assertEqual(report.evidence.get("hard_block_reasons"), reason)

    def test_another_radios_switch_cannot_substitute_for_missing_or_invalid_evidence(self):
        unrelated = self.root / "devices/another-radio/rfkill4"
        unrelated.mkdir(parents=True)
        (self.root / "class/rfkill/rfkill4").symlink_to(unrelated)
        for key, value in {"type": "wlan", "hard": "0", "soft": "0"}.items():
            (unrelated / key).write_text(value)
        for name, value in (("soft", "unexpected"), ("type", "bluetooth")):
            (self.switch / name).write_text(value)
            report = audit_adapter("wlan0", sysfs=self.root)
            self.assertEqual([check.status for check in report.checks], ["pass", "unknown"])
            self.assertNotIn("hard_blocked", report.evidence)
        (self.root / "class/rfkill/rfkill27").unlink()
        self.assertEqual(audit_adapter("wlan0", sysfs=self.root).result, "unknown")

    def test_hot_unplug_during_read_discards_the_partial_binding(self):
        def unplug(phy, entries):
            state = read_radio_switch(phy, entries)
            self.phy_link.unlink()
            return state

        with patch("radio_audit.adapter.read_radio_switch", side_effect=unplug):
            report = audit_adapter("wlan0", sysfs=self.root)
        self.assertEqual(report.result, "unknown")
        self.assertFalse(report.evidence)

    def test_cli_handles_a_non_wireless_interface_and_rejects_paths(self):
        result = invoke("adapter", "--device", "lo", "--json")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["scope"], "linux.wireless_adapter")
        for name in ("../private", ".", "..", "", "a" * 16):
            with self.subTest(name=name), self.assertRaises(AuditError):
                audit_adapter(name, sysfs=self.root)
