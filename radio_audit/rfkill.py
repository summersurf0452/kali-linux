import re
from pathlib import Path

from .report import Check

# Linux UAPI rfkill flags (ISC).
# https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/rfkill.h
# Copyright (C) 2006 - 2007 Ivo van Doorn
# Copyright (C) 2007 Dmitry Torokhov
# Copyright 2009 Johannes Berg <johannes@sipsolutions.net>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
RFKILL_HARD_BLOCK_SIGNAL = 1 << 0
RFKILL_HARD_BLOCK_NOT_OWNER = 1 << 1


def _hard_reasons(switch: Path) -> str:
    try:
        raw = (switch / "hard_block_reasons").read_bytes().strip()
    except FileNotFoundError:
        return "not_reported"
    if not re.fullmatch(rb"0x[0-9a-fA-F]{1,16}", raw):
        return "unknown"
    flags = int(raw, 16)
    reasons = []
    if flags & RFKILL_HARD_BLOCK_SIGNAL:
        reasons.append("hardware_signal")
    if flags & RFKILL_HARD_BLOCK_NOT_OWNER:
        reasons.append("host_not_owner")
    if flags & ~(RFKILL_HARD_BLOCK_SIGNAL | RFKILL_HARD_BLOCK_NOT_OWNER):
        reasons.append("unknown_bits")
    return "+".join(reasons) or "not_reported"


def read_radio_switch(phy: Path, rfkill_class: Path) -> tuple[Check, dict[str, str | int]]:
    rule = "adapter.rfkill"
    unknown = Check(rule, "unknown", "이 무선 장치의 송신 차단 상태를 확인할 수 없습니다.")
    entries = (link.resolve() for link in rfkill_class.glob("rfkill[0-9]*"))
    switches = [entry for entry in entries if phy in entry.parents]
    if len(switches) != 1:
        return unknown, {}
    switch = switches[0]
    try:
        if (switch / "type").read_bytes().strip() != b"wlan":
            return unknown, {}
        soft = (switch / "soft").read_bytes().strip()
        hard = (switch / "hard").read_bytes().strip()
        if soft not in {b"0", b"1"} or hard not in {b"0", b"1"}:
            return unknown, {}
        evidence: dict[str, str | int] = {"soft_blocked": int(soft), "hard_blocked": int(hard)}
        if hard == b"1":
            evidence["hard_block_reasons"] = _hard_reasons(switch)
    except FileNotFoundError:
        return unknown, {}
    if hard == b"1" or soft == b"1":
        return Check(rule, "fail", "rfkill에 이 무선 장치의 송신 차단이 기록돼 있습니다."), evidence
    return Check(
        rule, "pass", "이 무선 장치의 하드웨어·소프트웨어 차단이 모두 해제돼 있습니다."
    ), evidence
