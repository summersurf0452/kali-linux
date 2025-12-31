import re
from pathlib import Path

from .blocklist import check_blocklist
from .report import AuditError, Check, Report

POLICY_MIN_LENGTH = 16


def _repetition(value: str) -> Check:
    rule = "credential.repetition"
    for width in range(1, min(4, len(value) // 2) + 1):
        unit = value[:width]
        if unit * (len(value) // width) == value:
            return Check(rule, "fail", "입력 전체가 같은 1~4글자 단위로 반복됩니다.")
    return Check(rule, "pass", "입력 전체를 이루는 1~4글자 반복 단위가 없습니다.")


def audit_passphrase(value: str, mode: str, blocklist: Path | None = None) -> Report:
    if mode not in {"wpa-psk", "sae"}:
        raise AuditError("지원하는 인증 방식은 wpa-psk와 sae입니다.")
    scope = f"credential.{mode}"
    if mode == "wpa-psk" and re.fullmatch(r"[0-9A-Fa-f]{64}", value):
        return Report(
            scope,
            (
                Check("credential.format", "pass", "64자리 16진수 원시 PSK 형식입니다."),
                _repetition(value.lower()),
                Check(
                    "credential.key_origin",
                    "unknown",
                    "키가 무작위로 생성됐는지는 입력값만으로 확인할 수 없습니다.",
                ),
            ),
        )

    if mode == "wpa-psk" and not re.fullmatch(r"[ -~]{8,63}", value):
        return Report(
            scope,
            (
                Check(
                    "credential.format",
                    "fail",
                    "WPA-PSK에는 인쇄 가능한 ASCII 8~63자 또는 64자리 16진수 키가 필요합니다.",
                ),
            ),
        )
    if not value or any(char in value for char in ("\x00", "\r", "\n")):
        return Report(
            scope,
            (
                Check(
                    "credential.format",
                    "fail",
                    "이 도구에서 SAE 입력은 비어 있지 않은 한 줄의 텍스트여야 합니다.",
                ),
            ),
        )

    return Report(
        scope,
        (
            Check("credential.format", "pass", f"{mode} 패스프레이즈 입력 형식에 맞습니다."),
            Check(
                "credential.length",
                "pass" if len(value) >= POLICY_MIN_LENGTH else "fail",
                f"이 도구의 패스프레이즈 길이 기준은 {POLICY_MIN_LENGTH}자 이상입니다.",
            ),
            _repetition(value),
            check_blocklist(value, blocklist),
        ),
    )
