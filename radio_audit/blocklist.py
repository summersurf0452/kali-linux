import hashlib
import re
from pathlib import Path

from .report import AuditError, Check


def check_blocklist(passphrase: str, path: Path | None) -> Check:
    rule = "credential.blocklist"
    if path is None:
        return Check(rule, "unknown", "로컬 차단 목록을 지정하지 않아 대조하지 않았습니다.")

    digest = hashlib.sha256(passphrase.encode("utf-8")).hexdigest().encode("ascii")
    found = False
    entries = 0
    try:
        with path.open("rb") as source:
            for line_number, line in enumerate(iter(lambda: source.readline(67), b""), 1):
                entry = line.removesuffix(b"\n").removesuffix(b"\r")
                if not entry:
                    continue
                if not re.fullmatch(rb"[0-9A-Fa-f]{64}", entry):
                    raise AuditError(f"차단 목록의 {line_number}번째 줄이 SHA-256 형식이 아닙니다.")
                entries += 1
                if entry.lower() == digest:
                    found = True
    except OSError:
        raise AuditError("로컬 차단 목록을 읽을 수 없습니다.") from None
    if not entries:
        raise AuditError("로컬 차단 목록에 대조할 항목이 없습니다.")
    if found:
        return Check(rule, "fail", "입력값이 지정한 로컬 차단 목록과 일치합니다.")
    return Check(rule, "pass", "지정한 로컬 차단 목록에 일치하는 항목이 없습니다.")
