import os
import subprocess
from uuid import UUID

from radio_audit.profile import SECURITY_FIELDS
from radio_audit.report import AuditError

SECURITY_SECTION = "802-11-wireless-security."


def _read_fields(fields: tuple[str, ...], *command: str) -> dict[str, str]:
    args = [
        "nmcli",
        "--colors",
        "no",
        "--terse",
        "--mode",
        "multiline",
        "--escape",
        "no",
        "--fields",
        ",".join(fields),
        *command,
    ]
    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            check=True,
            timeout=6,
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError:
        raise AuditError("프로필 조회에는 NetworkManager의 nmcli가 필요합니다.") from None
    except subprocess.TimeoutExpired:
        raise AuditError("NetworkManager가 제한 시간 안에 응답하지 않았습니다.") from None
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        raise AuditError(
            "NetworkManager에서 요청한 장치 또는 프로필을 조회할 수 없습니다."
        ) from None

    result = {}
    for line in completed.stdout.splitlines():
        key, _, value = line.partition(":")
        if key in fields:
            value = value.strip()
            result[key] = "" if value == "--" else value
    return result


def _active_uuid(device: str) -> str:
    if not device or device.startswith("-") or any(char in device for char in "\r\n\0"):
        raise AuditError("무선랜 인터페이스 이름을 확인하세요.")
    data = _read_fields(("GENERAL.TYPE", "GENERAL.CON-UUID"), "device", "show", device)
    if data.get("GENERAL.TYPE") != "wifi":
        raise AuditError("선택한 장치가 Wi-Fi 인터페이스로 인식되지 않았습니다.")
    if not data.get("GENERAL.CON-UUID"):
        raise AuditError("선택한 무선랜에 활성 연결이 없습니다.")
    return data["GENERAL.CON-UUID"]


def _read_profile(identifier: str) -> dict[str, str]:
    try:
        profile_uuid = str(UUID(identifier))
    except ValueError:
        raise AuditError("연결 프로필의 UUID 형식을 확인하세요.") from None
    fields = (
        "connection.type",
        "connection.uuid",
        *(SECURITY_SECTION + key for key in SECURITY_FIELDS),
    )
    data = _read_fields(fields, "connection", "show", "uuid", profile_uuid)
    if data.get("connection.uuid") != profile_uuid:
        raise AuditError("요청한 프로필의 UUID를 확인할 수 없습니다.")
    if data.get("connection.type") not in {"802-11-wireless", "wifi"}:
        raise AuditError("선택한 프로필은 Wi-Fi 연결 프로필이어야 합니다.")
    return {key: data.get(SECURITY_SECTION + key, "") for key in SECURITY_FIELDS}


def read_profile(*, device: str | None, profile_uuid: str | None) -> dict[str, str]:
    if device is None:
        if profile_uuid is None:
            raise AuditError("무선랜 장치 또는 저장 프로필 UUID가 필요합니다.")
        return _read_profile(profile_uuid)
    active = _active_uuid(device)
    profile = _read_profile(active)
    if _active_uuid(device) != active:
        raise AuditError("조회 중 활성 연결이 바뀌었습니다. 다시 실행하세요.")
    return profile
