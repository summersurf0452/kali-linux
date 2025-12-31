import argparse
import getpass
import json
import sys
import warnings
from contextlib import nullcontext
from pathlib import Path
from typing import NoReturn

from radio_audit.adapter import audit_adapter
from radio_audit.auth_log import (
    DEFAULT_MIN_EVENTS,
    DEFAULT_WINDOW_SECONDS,
    audit_auth_log,
)
from radio_audit.passphrase import audit_passphrase
from radio_audit.profile import audit_profile
from radio_audit.report import AuditError, Report

from .networkmanager import read_profile

MAX_INPUT_BYTES = 16384
EXIT_CODES = {"pass": 0, "fail": 1, "unknown": 3}
EXIT_HELP = "종료 코드 0은 점검 통과, 1은 기준 미달, 2는 실행 오류, 3은 확인 불가입니다."


class AuditParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(
            2,
            "인수를 확인하세요. 각 명령의 --help에서 입력 형식을 볼 수 있습니다.\n",
        )


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = AuditParser(
        prog="python3 -m console",
        description="내 무선랜 장치, Wi-Fi 인증 설정, hostapd 기록을 점검합니다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "python3 -m console adapter --device wlan0\npython3 -m console passphrase --mode sae\n"
            "python3 -m console profile --device wlan0 --json\n"
            f"python3 -m console auth-log hostapd.jsonl --json\n\n{EXIT_HELP}"
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    adapter = commands.add_parser(
        "adapter",
        help="커널에 등록된 무선 장치와 드라이버 확인",
        description="sysfs에서 지정한 무선 장치의 버스, 드라이버와 rfkill 송신 차단 상태를 읽습니다.",
        epilog=EXIT_HELP,
    )
    adapter.add_argument(
        "--device", required=True, metavar="IFACE", help="확인할 로컬 무선랜 인터페이스"
    )
    phrase = commands.add_parser("passphrase", help="직접 입력한 비밀번호 점검", epilog=EXIT_HELP)
    phrase.add_argument(
        "--mode",
        choices=["wpa-psk", "sae"],
        default="wpa-psk",
        help="패스프레이즈 입력 형식 (기본값 wpa-psk)",
    )
    phrase.add_argument(
        "--blocklist",
        type=Path,
        metavar="FILE",
        help="UTF-8 원문의 SHA-256을 줄마다 16진수 하나씩 저장한 로컬 차단 목록. 생략하면 이 검사는 unknown",
    )
    phrase.add_argument(
        "--stdin",
        action="store_true",
        help="파이프에서 UTF-8 한 줄 입력 (터미널 기본값은 숨김 입력)",
    )
    profile = commands.add_parser(
        "profile",
        help="NetworkManager에 저장된 Wi-Fi 설정 점검",
        description="인증과 암호화를 요구하는 Wi-Fi 기준으로 저장 프로필을 읽습니다. 결과의 범위는 프로필에 명시된 설정입니다.",
        epilog=EXIT_HELP,
    )
    target = profile.add_mutually_exclusive_group(required=True)
    target.add_argument("--device", metavar="IFACE", help="현재 연결된 내 무선랜 인터페이스")
    target.add_argument(
        "--uuid",
        dest="profile_uuid",
        metavar="UUID",
        help="내 시스템에 저장된 Wi-Fi 연결 프로필 UUID",
    )
    auth_log = commands.add_parser(
        "auth-log",
        help="내 hostapd AP의 반복 인증 실패 신호 점검",
        description=(
            "journalctl -o json으로 내보낸 hostapd 기록에서 인터페이스와 단말을 식별할 수 있는 "
            "AP-STA-POSSIBLE-PSK-MISMATCH 이벤트를 셉니다. 같은 인증 시도도 여러 기록을 남길 수 있습니다."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "내 AP가 hostapd.service를 사용하는 경우\n"
            "journalctl -u hostapd --no-pager -o json | python3 -m console auth-log - --json\n\n"
            + EXIT_HELP
        ),
    )
    auth_log.add_argument(
        "journal", metavar="FILE", help="저널 JSON Lines 파일 경로 (표준 입력은 -)"
    )
    auth_log.add_argument(
        "--window-seconds",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help=f"반복 여부를 볼 구간 (기본 {DEFAULT_WINDOW_SECONDS}초)",
    )
    auth_log.add_argument(
        "--min-events",
        type=int,
        default=DEFAULT_MIN_EVENTS,
        help=f"한 구간의 최소 신호 수 (기본 {DEFAULT_MIN_EVENTS}건)",
    )
    for subparser in (adapter, phrase, profile, auth_log):
        subparser.add_argument("--json", action="store_true", help="결과를 JSON으로 출력")
    return parser.parse_args(argv)


def _read_secret(use_stdin: bool) -> str:
    if use_stdin:
        if sys.stdin.isatty():
            raise AuditError("터미널에서는 --stdin을 빼고 숨김 입력을 사용하세요.")
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 3)
        if not raw:
            raise AuditError("표준 입력이 비어 있습니다.")
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        if len(raw) > MAX_INPUT_BYTES or b"\r" in raw or b"\n" in raw:
            raise AuditError("표준 입력은 16 KiB 이하의 UTF-8 한 줄이어야 합니다.")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise AuditError("표준 입력은 UTF-8 텍스트여야 합니다.") from None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("점검할 내 Wi-Fi 비밀번호: ")
    except (getpass.GetPassWarning, EOFError, OSError):
        raise AuditError(
            "숨김 입력이 가능한 터미널을 사용하거나 파이프에서 --stdin을 지정하세요."
        ) from None
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise AuditError("터미널 입력은 UTF-8 텍스트여야 합니다.") from None
    if size > MAX_INPUT_BYTES:
        raise AuditError("이 도구의 비밀번호 입력 한도는 16 KiB입니다.")
    return value


def _audit_journal(args: argparse.Namespace) -> Report:
    try:
        with (
            nullcontext(sys.stdin.buffer) if args.journal == "-" else Path(args.journal).open("rb")
        ) as source:
            return audit_auth_log(
                source, window_seconds=args.window_seconds, min_events=args.min_events
            )
    except OSError:
        raise AuditError("저널 입력을 읽을 수 없습니다.") from None


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    try:
        if args.command == "adapter":
            report = audit_adapter(args.device)
        elif args.command == "passphrase":
            report = audit_passphrase(_read_secret(args.stdin), args.mode, args.blocklist)
        elif args.command == "auth-log":
            report = _audit_journal(args)
        else:
            settings = read_profile(device=args.device, profile_uuid=args.profile_uuid)
            report = audit_profile(settings)
    except AuditError as error:
        if args.json:
            print(
                json.dumps(
                    {"schema_version": 1, "result": "error", "message": str(error)},
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
        else:
            print(error, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130

    if args.json:
        print(json.dumps(report.as_dict(), ensure_ascii=False))
    else:
        print(f"{report.scope}  {report.result}")
        for check in report.checks:
            print(f"[{check.status}] {check.id}  {check.message}")
        for name, value in report.evidence.items():
            print(f"  {name}={value}")
    return EXIT_CODES[report.result]


if __name__ == "__main__":
    sys.exit(main())
