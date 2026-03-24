import re
from pathlib import Path
from typing import List

from .models import Finding
from .rules import RULES


def scan_file(filepath: str) -> List[Finding]:
    # CHANGE: scanner engine extracted from legacy UI for reuse by CLI and PySide6 desktop app
    findings: List[Finding] = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return findings

    for rule in RULES:
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in rule.patterns]
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for compiled_pattern in compiled_patterns:
                match = compiled_pattern.search(line)
                if match is None:
                    continue

                is_false_positive = any(
                    hint.lower() in line.lower()
                    for hint in rule.false_positive_hints
                    if hint != "//"
                )
                if not is_false_positive:
                    findings.append(
                        Finding(
                            rule=rule,
                            line_no=line_no,
                            line_text=line.rstrip(),
                            match_text=match.group(0),
                            filepath=filepath,
                        )
                    )
                break

    return findings


def scan_target(path_value: str) -> List[Finding]:
    # CHANGE: centralize file-or-directory scanning so all entrypoints share identical behavior
    findings: List[Finding] = []
    path = Path(path_value)
    if path.is_file():
        findings.extend(scan_file(str(path)))
    elif path.is_dir():
        for file_path in path.rglob("*.cs"):
            findings.extend(scan_file(str(file_path)))

    findings.sort(
        key=lambda finding: (
            -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[finding.rule.severity],
            finding.filepath,
            finding.line_no,
        )
    )
    return findings


def get_context(filepath: str, line_no: int, radius: int = 4) -> str:
    # CHANGE: expose reusable code-context rendering for the new desktop detail panel and CLI exports
    try:
        with open(filepath, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return ""

    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    result: List[str] = []
    for index, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if index == line_no else "   "
        result.append(f"{marker} {index:4}: {line.rstrip()}")
    return "\n".join(result)
