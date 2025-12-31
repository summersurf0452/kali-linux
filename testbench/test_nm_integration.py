# python-dbusmock NetworkManager template (LGPL-3.0-or-later).
# https://github.com/martinpitt/python-dbusmock/blob/0.31.1/dbusmock/templates/networkmanager.py

import json
import os
import shutil
import subprocess
import unittest
from unittest.mock import patch
from uuid import uuid4

from testbench.test_cli import invoke

try:
    import dbus
    from dbusmock import MOCK_IFACE, BusType, PrivateDBus, SpawnedMock
    from dbusmock.templates import networkmanager as nm
except ImportError:
    dbus = None


@unittest.skipUnless(
    dbus and shutil.which("nmcli") and shutil.which("dbus-daemon"),
    "requires nmcli, dbus-daemon and python3-dbusmock",
)
class NativeProfileTests(unittest.TestCase):
    def test_saved_and_active_profiles_via_real_nmcli(self):
        version = subprocess.check_output(["nmcli", "--version"], text=True).strip().split()[-1]
        with (
            patch.dict(os.environ),
            PrivateDBus(BusType.SYSTEM),
            SpawnedMock.spawn_with_template("networkmanager", {"Version": version}) as service,
        ):
            mock = dbus.Interface(service.obj, MOCK_IFACE)
            device = mock.AddWiFiDevice("1", "wlanlab0", 30)
            settings = dbus.Interface(
                BusType.SYSTEM.get_connection().get_object(nm.BUS_NAME, nm.SETTINGS_OBJ),
                nm.SETTINGS_IFACE,
            )
            for mode, expected in (("sae", 0), ("open", 1)):
                identifier = str(uuid4())
                profile = {
                    "connection": {
                        "id": "synthetic-profile",
                        "uuid": identifier,
                        "type": "802-11-wireless",
                    },
                    "802-11-wireless": {
                        "ssid": dbus.ByteArray(b"synthetic-ssid"),
                        "mode": "infrastructure",
                    },
                }
                if mode == "sae":
                    profile["802-11-wireless-security"] = {
                        "key-mgmt": "sae",
                        "pmf": dbus.Int32(3),
                        "proto": dbus.Array(["rsn"], signature="s"),
                        "pairwise": dbus.Array(["ccmp"], signature="s"),
                        "group": dbus.Array(["ccmp"], signature="s"),
                    }
                saved = settings.AddConnection(profile)
                targets = [("--uuid", identifier)]
                if mode == "sae":
                    mock.AddActiveConnection([device], saved, "/", "1", 2)
                    targets.append(("--device", "wlanlab0"))
                for flag, value in targets:
                    with self.subTest(mode=mode, selector=flag):
                        result = invoke("profile", flag, value, "--json")
                        self.assertEqual(result.returncode, expected, result.stderr.decode())
                        data = json.loads(result.stdout)
                        self.assertEqual(data["result"], "pass" if mode == "sae" else "fail")
                        if mode == "sae":
                            self.assertEqual(data["evidence"]["configured_generation"], "wpa3_only")
                            self.assertEqual(
                                data["evidence"]["negotiated_generation"], "not_observed"
                            )
                        for private in (identifier, "synthetic-ssid", "synthetic-profile"):
                            self.assertNotIn(private.encode(), result.stdout + result.stderr)
