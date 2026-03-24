import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import List

from .models import Finding
from .rules import APP_NAME, APP_VERSION


def export_txt(findings: List[Finding], filepath: str) -> None:
    # CHANGE: keep export formats independent from any GUI framework
    with open(filepath, "w", encoding="utf-8") as handle:
        handle.write(f"=== {APP_NAME} v{APP_VERSION} ===\n")
        handle.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        handle.write(f"Всего проблем: {len(findings)}\n\n")
        for finding in findings:
            handle.write(f"[{finding.rule.severity}] {finding.rule.id}\n")
            handle.write(f"Файл: {Path(finding.filepath).name}\n")
            handle.write(f"Строка: {finding.line_no}\n")
            handle.write(f"Название: {finding.rule.title}\n")
            handle.write(f"Код: {finding.line_text}\n")
            handle.write(f"Совпадение: {finding.match_text}\n")
            handle.write(f"\n{'-' * 60}\n\n")


def export_json(findings: List[Finding], filepath: str) -> None:
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanner_version": APP_VERSION,
        "total_findings": len(findings),
        "findings": [
            {
                "severity": finding.rule.severity,
                "id": finding.rule.id,
                "category": finding.rule.category,
                "title": finding.rule.title,
                "file": Path(finding.filepath).name,
                "line": finding.line_no,
                "code": finding.line_text,
                "match": finding.match_text,
            }
            for finding in findings
        ],
    }
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def export_html(findings: List[Finding], filepath: str) -> None:
    findings_markup = []
    for finding in findings:
        severity_class = finding.rule.severity.lower()
        findings_markup.append(
            f"""
    <div class=\"finding {severity_class}\">
        <span class=\"severity {severity_class}-badge\">{escape(finding.rule.severity)}</span>
        <strong>{escape(finding.rule.id)}: {escape(finding.rule.title)}</strong>
        <p>{escape(finding.rule.description)}</p>
        <p class=\"meta\">Файл: {escape(Path(finding.filepath).name)} | Строка: {finding.line_no}</p>
        <code>{escape(finding.line_text)}</code>
    </div>
"""
        )

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset=\"UTF-8\">
    <title>{escape(APP_NAME)} - Отчёт</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0b1320; color: #e2e8f0; margin: 24px; }}
        h1 {{ color: #8bd5ff; }}
        .finding {{ background: #121b2d; padding: 15px; margin: 10px 0; border-radius: 12px; border-left: 4px solid; }}
        .critical {{ border-color: #ff2020; }}
        .high {{ border-color: #ff7700; }}
        .medium {{ border-color: #ffcc00; }}
        .low {{ border-color: #44aaff; }}
        .info {{ border-color: #aaaaaa; }}
        .severity {{ font-weight: bold; padding: 4px 8px; border-radius: 999px; display: inline-block; margin-bottom: 10px; }}
        .critical-badge {{ background: #ff2020; color: white; }}
        .high-badge {{ background: #ff7700; color: white; }}
        .medium-badge {{ background: #ffcc00; color: black; }}
        .low-badge {{ background: #44aaff; color: white; }}
        .info-badge {{ background: #aaaaaa; color: white; }}
        code {{ background: #09111d; padding: 4px 8px; border-radius: 6px; color: #f8c537; display: inline-block; margin-top: 8px; }}
        .meta {{ color: #94a3b8; font-size: 0.95em; }}
    </style>
</head>
<body>
    <h1>{escape(APP_NAME)} v{escape(APP_VERSION)}</h1>
    <p class=\"meta\">Дата сканирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p class=\"meta\">Всего проблем: {len(findings)}</p>
    <hr>
    {''.join(findings_markup)}
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as handle:
        handle.write(html)
