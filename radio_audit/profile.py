from collections.abc import Mapping

from .report import Check, Report

SECURITY_FIELDS = ("key-mgmt", "pmf", "proto", "pairwise", "group")
SCOPE = "networkmanager.saved_profile"
AUTHENTICATED = {
    "wpa-psk": "WPA-Personal",
    "sae": "WPA3-Personal (SAE)",
    "wpa-eap": "WPA-Enterprise",
    "wpa-eap-suite-b-192": "WPA3-Enterprise Suite B 192",
}


def _values(raw: str) -> set[str]:
    return set(raw.lower().replace(",", " ").split())


def _configured_generation(key_mgmt: str, protocols: set[str]) -> str:
    if key_mgmt in {"sae", "wpa-eap-suite-b-192"}:
        return "inconsistent" if protocols == {"wpa"} else "wpa3_only"
    if protocols == {"wpa"}:
        return "legacy_wpa_only"
    if protocols == {"rsn"}:
        return "wpa2_or_wpa3"
    return "not_pinned"


def _allowed_algorithms(rule: str, values: set[str], legacy: set[str], accepted: set[str]) -> Check:
    if values & legacy:
        names = ", ".join(sorted(values & legacy))
        return Check(rule, "fail", f"프로필이 허용하는 레거시 방식에 {names} 항목이 포함됩니다.")
    if not values:
        return Check(rule, "unknown", "프로필에 허용 목록을 명시하지 않았습니다.")
    if values - accepted:
        return Check(rule, "unknown", "이 도구에서 해석하지 않는 설정값이 있습니다.")
    return Check(
        rule, "pass", "프로필이 명시적으로 허용하는 값은 " + ", ".join(sorted(values)) + "입니다."
    )


def _pmf(raw: str) -> Check:
    rule = "profile.pmf"
    value = raw.split(maxsplit=1)[0].lower() if raw else ""
    if value in {"3", "required"}:
        return Check(rule, "pass", "프로필이 관리 프레임 보호(PMF)를 요구합니다.")
    if value in {"1", "disable", "disabled"}:
        return Check(rule, "fail", "프로필이 관리 프레임 보호(PMF)를 비활성화합니다.")
    if value in {"2", "optional"}:
        return Check(
            rule,
            "unknown",
            "PMF가 선택 사항입니다. 실제 사용 여부는 프로필에서 확인할 수 없습니다.",
        )
    if value in {"", "0", "default"}:
        return Check(
            rule, "unknown", "PMF가 기본값을 따릅니다. 프로필에 강제 여부를 명시하지 않았습니다."
        )
    return Check(rule, "unknown", "이 도구에서 해석하지 않는 PMF 설정값입니다.")


def audit_profile(fields: Mapping[str, str]) -> Report:
    rule = "profile.authentication"
    key_mgmt = fields.get("key-mgmt", "").strip().lower()
    if not any(fields.values()):
        return Report(
            SCOPE, (Check(rule, "fail", "이 Wi-Fi 프로필에 인증이나 암호화 설정이 없습니다."),)
        )
    if key_mgmt in {"none", "ieee8021x"}:
        return Report(SCOPE, (Check(rule, "fail", "개방형 또는 구형 WEP 계열 인증 설정입니다."),))
    if key_mgmt == "owe":
        return Report(
            SCOPE,
            (
                Check(
                    rule,
                    "fail",
                    "OWE는 연결을 암호화하지만 AP를 인증하지 않아 이 점검의 인증 기준에 미달합니다.",
                ),
            ),
        )
    if key_mgmt not in AUTHENTICATED:
        return Report(
            SCOPE, (Check(rule, "unknown", "프로필의 키 관리 방식을 판정할 수 없습니다."),)
        )

    protocols = _values(fields.get("proto", ""))
    checks = [
        Check(rule, "pass", f"프로필의 키 관리 방식은 {AUTHENTICATED[key_mgmt]}입니다."),
        _pmf(fields.get("pmf", "").strip()),
        _allowed_algorithms("profile.protocol", protocols, {"wpa"}, {"rsn"}),
    ]
    for field in ("pairwise", "group"):
        checks.append(
            _allowed_algorithms(
                f"profile.{field}",
                _values(fields.get(field, "")),
                {"wep40", "wep104", "tkip"},
                {"ccmp", "ccmp-256", "gcmp", "gcmp-256"},
            )
        )
    if key_mgmt in {"wpa-eap", "wpa-eap-suite-b-192"}:
        checks.append(
            Check(
                "profile.eap_identity",
                "unknown",
                "별도 EAP 설정의 서버 인증서 검증 여부는 확인하지 않았습니다.",
            )
        )
    return Report(
        SCOPE,
        tuple(checks),
        {
            "configured_generation": _configured_generation(key_mgmt, protocols),
            "negotiated_generation": "not_observed",
        },
    )
