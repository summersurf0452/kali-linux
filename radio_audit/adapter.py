import errno
import os
from pathlib import Path

from .report import AuditError, Check, Report
from .rfkill import read_radio_switch


def _driver_binding(phy: Path, devices: Path) -> tuple[str, str] | None:
    for parent in phy.parents:
        if parent == devices or devices not in parent.parents:
            break
        subsystem = parent / "subsystem"
        if subsystem.is_symlink():
            bus = subsystem.resolve(strict=True).name
            driver = (parent / "driver").resolve(strict=True).name
            return bus, driver
    return None


def audit_adapter(device: str, *, sysfs: Path = Path("/sys")) -> Report:
    if (
        not device
        or device in {".", ".."}
        or len(os.fsencode(device)) >= 16
        or any(c in "/:\0" or c.isspace() for c in device)
    ):
        raise AuditError("무선랜 인터페이스 이름을 확인하세요.")

    scope = "linux.wireless_adapter"
    rule = "adapter.driver_binding"
    unknown = Report(
        scope,
        (
            Check(
                rule, "unknown", "이 인터페이스의 무선 장치와 드라이버 연결을 확인할 수 없습니다."
            ),
        ),
    )
    phy_link = sysfs / "class" / "net" / device / "phy80211"
    try:
        observed = phy_link.stat()
        phy = phy_link.resolve(strict=True)
        index = (phy / "index").read_bytes().strip()
        binding = _driver_binding(phy, sysfs.resolve() / "devices")
        switch, switch_evidence = read_radio_switch(phy, sysfs / "class" / "rfkill")
        if not os.path.samestat(observed, phy_link.stat()):
            return unknown
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR, errno.ENODEV, errno.ENXIO}:
            return unknown
        raise AuditError("커널의 무선 장치 정보를 읽을 수 없습니다.") from None
    if binding is None or not index.isdigit() or len(index) > 10:
        return unknown
    bus, driver = binding
    return Report(
        scope,
        (Check(rule, "pass", "커널에서 무선 장치와 바인딩된 드라이버를 확인했습니다."), switch),
        {"wiphy_index": int(index), "bus": bus, "driver": driver, **switch_evidence},
    )
