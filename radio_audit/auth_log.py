import json
import re
from collections import defaultdict
from collections.abc import Iterator
from typing import BinaryIO

from .report import AuditError, Check, Report

DEFAULT_WINDOW_SECONDS = 60
DEFAULT_MIN_EVENTS = 5
_MAX_RECORD_BYTES = 1024 * 1024
_EVENT = re.compile(
    r"(?:(?P<interface>[^\s:]+):[ \t]+)?AP-STA-POSSIBLE-PSK-MISMATCH"
    r"(?:[ \t]+(?P<station>[^\s]+))?(?:[ \t]+[^\r\n]*)?"
)
_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_BOOT = re.compile(r"[0-9A-Fa-f]{32}")


def _records(source: BinaryIO) -> Iterator[dict[str, object]]:
    for number, line in enumerate(iter(lambda: source.readline(_MAX_RECORD_BYTES + 1), b""), 1):
        if len(line) > _MAX_RECORD_BYTES:
            raise AuditError(f"저널의 {number}번째 줄이 입력 한도 1 MiB를 넘습니다.")
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            raise AuditError(f"저널의 {number}번째 줄이 유효한 JSON이 아닙니다.") from None
        if not isinstance(row, dict):
            raise AuditError(f"저널의 {number}번째 줄에는 JSON 객체가 필요합니다.")
        yield row


def _hostapd_source(row: dict[str, object]) -> bool | None:
    if "_COMM" in row:
        return row["_COMM"] == "hostapd"
    unit = row.get("_SYSTEMD_UNIT")
    if isinstance(unit, str):
        return (
            unit == "hostapd.service" or re.fullmatch(r"hostapd@[^/]+\.service", unit) is not None
        )
    return None if row.get("SYSLOG_IDENTIFIER") == "hostapd" else False


def _usec(raw: object) -> int | None:
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,20}", raw):
        return None
    value = int(raw)
    return value if value < 2**64 else None


def audit_auth_log(
    source: BinaryIO,
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    min_events: int = DEFAULT_MIN_EVENTS,
) -> Report:
    if window_seconds < 1 or min_events < 2:
        raise AuditError("시간 구간은 1초 이상, 반복 기준은 2건 이상이어야 합니다.")
    groups: dict[tuple[str, str, str], list[tuple[int, int]]] = defaultdict(list)
    cursors: set[str] = set()
    duplicates = incomplete = 0
    for row in _records(source):
        hostapd_source = _hostapd_source(row)
        if hostapd_source is False:
            continue
        message = row.get("MESSAGE")
        if not isinstance(message, str):
            incomplete += 1
            continue
        match = _EVENT.fullmatch(message)
        if match is None:
            continue
        interface, station = match.groups()
        boot = row.get("_BOOT_ID")
        cursor = row.get("__CURSOR")
        mono = _usec(row.get("__MONOTONIC_TIMESTAMP"))
        wall = _usec(row.get("__REALTIME_TIMESTAMP"))
        if (
            hostapd_source is None
            or not interface
            or not station
            or not _MAC.fullmatch(station)
            or not isinstance(boot, str)
            or not _BOOT.fullmatch(boot)
            or not isinstance(cursor, str)
            or not cursor
            or mono is None
            or wall is None
        ):
            incomplete += 1
            continue
        if cursor in cursors:
            duplicates += 1
            continue
        cursors.add(cursor)
        groups[boot.lower(), interface, station.lower()].append((mono, wall))

    window_us = window_seconds * 1_000_000
    peak = alerted_groups = 0
    peak_end: int | None = None
    for events in groups.values():
        events.sort()
        left = group_peak = 0
        for right, (mono_now, wall_now) in enumerate(events):
            while mono_now - events[left][0] > window_us:
                left += 1
            count = right - left + 1
            group_peak = max(group_peak, count)
            if count > peak or (count == peak and peak_end is not None and wall_now < peak_end):
                peak, peak_end = count, wall_now
        alerted_groups += int(group_peak >= min_events)

    evidence: dict[str, str | int] = {
        "window_seconds": window_seconds,
        "min_events": min_events,
        "unique_signals": len(cursors),
        "duplicate_records": duplicates,
        "unusable_records": incomplete,
        "peak_window_signals": peak,
        "groups_over_threshold": alerted_groups,
    }
    if peak_end is not None:
        evidence["peak_end_realtime_us"] = peak_end

    rule = "auth_log.repeated_mismatch"
    if alerted_groups:
        result = Check(
            rule,
            "fail",
            "같은 부팅·무선 인터페이스·단말에서 키 불일치 의심 이벤트가 반복 기준에 도달했습니다.",
        )
    elif incomplete or not cursors:
        result = Check(
            rule, "unknown", "반복 여부를 판정할 수 있는 이벤트나 메타데이터가 충분하지 않습니다."
        )
    else:
        result = Check(rule, "pass", "관측한 키 불일치 의심 이벤트는 반복 기준 미만입니다.")
    return Report("hostapd.journal", (result,), evidence)
