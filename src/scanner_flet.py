"""
Rust Oxide Plugin Security Scanner - Modern UI
Advanced security scanner for Rust server plugins (Oxide/uMod framework)

This tool performs static code analysis to detect malicious patterns including:
- Privilege escalation attempts
- Remote code execution vectors
- Data exfiltration mechanisms
- Code obfuscation techniques
- SQL injection vulnerabilities

Author:  MMZ4
Version: 2.0.4
License: Educational purposes only
"""

import flet as ft
import re
import json
from dataclasses import dataclass, field
from typing import List
from pathlib import Path
from datetime import datetime

APP_NAME = "Rust Plugin Security Scanner"
APP_VERSION = "2.0.4"
APP_AUTHOR = "MMZ4"

# Security Detection Rules

@dataclass
class Rule:
    id: str
    severity: str
    category: str
    title: str
    description: str
    patterns: List[str]
    false_positive_hints: List[str] = field(default_factory=list)

@dataclass
class Finding:
    rule: Rule
    line_no: int
    line_text: str
    match_text: str
    filepath: str = ""

SEVERITY_COLOR = {
    "CRITICAL": "#ff2020",
    "HIGH": "#ff7700",
    "MEDIUM": "#ffcc00",
    "LOW": "#44aaff",
    "INFO": "#aaaaaa",
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


RULES: List[Rule] = [
    # Critical severity threats
    Rule("C001", "CRITICAL", "Admin Escalation",
         "Выдача прав администратора через ConsoleSystem",
         "Плагин выполняет команду ownerid/moderatorid через ConsoleSystem.Run",
         [r'ConsoleSystem\.Run\s*\([^)]*"ownerid', r'ConsoleSystem\.Run\s*\([^)]*"moderatorid',
          r'"ownerid\s+\d{17}', r'"moderatorid\s+\d{17}'],
         ["//", "example", "sample"]),
    
    Rule("C002", "CRITICAL", "Admin Escalation",
         "Прямое добавление в группу oxide.admin",
         "Плагин программно добавляет игроков в группу oxide.admin",
         [r'permission\.AddUserGroup\s*\([^)]*"oxide\.admin"',
          r'ServerUsers\.Set\s*\([^,]+,\s*ServerUsers\.UserGroup\.Owner'],
         ["//", "hasPermission"]),
    
    Rule("C003", "CRITICAL", "Remote Code Execution",
         "Запуск системных процессов / shell-команд",
         "Плагин создаёт системный процесс (cmd.exe, powershell, bash)",
         [r'System\.Diagnostics\.Process', r'ProcessStartInfo', r'Process\.Start\s*\(',
          r'"cmd\.exe"', r'"powershell"', r'"/bin/bash"'],
         ["//"]),
    
    Rule("C004", "CRITICAL", "Remote Code Execution",
         "Динамическая компиляция и выполнение кода",
         "Плагин компилирует и выполняет код в рантайме",
         [r'Assembly\.Load\s*\(', r'Assembly\.LoadFrom\s*\(',
          r'Activator\.CreateInstance.*Assembly'],
         ["//", "Activator.CreateInstance<T>()"]),
    
    Rule("C005", "CRITICAL", "Data Exfiltration",
         "Отправка данных на жёстко прописанный URL",
         "Плагин отправляет HTTP-запросы на неизвестный URL",
         [r'WebClient\s*\(', r'HttpClient\s*\(',
          r'webrequest\.Enqueue\s*\(["\']https?://(?!api\.steampowered|discord\.com|umod\.org)'],
         ["//", "api.steampowered", "discord"]),
    
    Rule("C006", "CRITICAL", "Reflection",
         "Вызов ConsoleSystem через рефлексию",
         "Плагин вызывает ConsoleSystem.Run через рефлексию для скрытия",
         [r'Type\.GetType\s*\(\s*"ConsoleSystem', r'GetMethod\s*\(\s*"Run"'],
         ["//"]),
    
    Rule("C007", "CRITICAL", "Reflection",
         "Динамический вызов Process.Start через рефлексию",
         "Плагин запускает процессы через рефлексию",
         [r'Type\.GetType\s*\(\s*"System\.Diagnostics\.Process'],
         ["//"]),
    
    # High severity threats
    Rule("H001", "HIGH", "Data Exfiltration",
         "Отправка SteamID / IP-адресов на внешний сервер",
         "Плагин собирает SteamID или IP-адреса игроков и отправляет их",
         [r'player\.UserIDString.*webrequest', r'player\.net\.connection\.ipaddress.*webrequest',
          r'ip-api\.com', r'ipinfo\.io'],
         ["//", "discord", "ban"]),
    
    Rule("H002", "HIGH", "File System",
         "Запись/удаление произвольных файлов на сервере",
         "Плагин пишет или удаляет файлы за пределами стандартных директорий",
         [r'File\.Delete\s*\(', r'File\.WriteAllText\s*\(', r'File\.WriteAllBytes\s*\(',
          r'Directory\.Delete\s*\('],
         ["//", "oxide/data", "config/"]),
    
    Rule("H003", "HIGH", "Obfuscation",
         "Base64-декодирование строк в рантайме",
         "Плагин декодирует строки из Base64 во время выполнения",
         [r'Convert\.FromBase64String\s*\('],
         ["//", "ImageLibrary"]),
    
    Rule("H004", "HIGH", "Harmony Patch",
         "Потенциально опасный Harmony-патч",
         "Плагин использует Harmony для патча игровых методов",
         [r'\[HarmonyPatch\(', r'harmony\.Patch\s*\('],
         ["//"]),
    
    Rule("H005", "HIGH", "Credentials",
         "Жёстко прописанные SteamID",
         "В коде найдены жёстко прописанные SteamID64",
         [r'(?<!\w)7656119\d{10}(?!\d)'],
         ["//", "example", "test", "0"]),
    
    Rule("H006", "HIGH", "Obfuscation",
         "XOR-шифрование строк в рантайме",
         "Плагин использует XOR для шифрования строк",
         [r'\[\w+\]\s*\^=', r'data\[i\]\s*\^='],
         ["//", "checksum"]),
    
    Rule("H007", "HIGH", "Obfuscation",
         "Динамическая сборка строк из частей",
         "Строки собираются из частей в рантайме",
         [r'string\.Concat\s*\(', r'string\.Join\s*\(\s*""'],
         ["//", "config"]),
    
    Rule("H008", "HIGH", "Obfuscation",
         "Многослойное шифрование данных",
         "Данные проходят через несколько слоёв шифрования",
         [r'Convert\.FromBase64String.*\^=', r'Array\.Reverse.*Convert\.FromBase64'],
         ["//"]),
    
    Rule("H009", "HIGH", "Reflection",
         "Создание делегатов через рефлексию",
         "Плагин создаёт делегаты динамически",
         [r'Delegate\.CreateDelegate\s*\('],
         ["//"]),
    
    Rule("H010", "HIGH", "Reflection",
         "Использование Expression Trees",
         "Плагин использует LINQ Expressions для генерации кода",
         [r'Expression\.Parameter\s*\(', r'Expression\.Call\s*\(', r'\.Compile\s*\(\s*\)'],
         ["//"]),
    
    # Medium severity threats
    Rule("M001", "MEDIUM", "SQL Injection",
         "SQL-запрос с интерполяцией строк",
         "SQL-запрос формируется через конкатенацию без параметризации",
         [r'Sql\.Builder\.Append\s*\(\s*\$"[^"]*\{', r'"SELECT.*WHERE.*\+\s*\w'],
         ["//", "@0"]),
    
    Rule("M002", "MEDIUM", "Reflection",
         "Использование рефлексии для вызова методов",
         "Плагин использует рефлексию для динамического вызова методов",
         [r'Type\.GetMethod\s*\(', r'MethodInfo\.Invoke\s*\('],
         ["//"]),
    
    Rule("M003", "MEDIUM", "Network",
         "Отправка данных через Discord Webhook",
         "Плагин отправляет данные на Discord webhook",
         [r'"https://discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"'],
         ["//", "config."]),
    
    Rule("M004", "MEDIUM", "Data Exfiltration",
         "Hardcoded API-ключ в коде",
         "В коде найден жёстко прописанный API-ключ или токен",
         [r'apiKey\s*=\s*"[A-Za-z0-9]{20,}"', r'token\s*=\s*"[A-Za-z0-9]{30,}"'],
         ["//", "config."]),
    
    Rule("M005", "MEDIUM", "Obfuscation",
         "Шифрование с жёстко прописанным ключом",
         "Плагин использует симметричное шифрование с ключом в коде",
         [r'Aes\.Create\s*\(', r'aes\.Key\s*=\s*Convert\.FromBase64String'],
         ["//"]),
    
    Rule("M006", "MEDIUM", "Obfuscation",
         "Использование char[] вместо строк",
         "Строки создаются из массивов char",
         [r'char\[\]\s+\w+\s*=\s*\{\s*\'[^\']\'\s*,'],
         ["//"]),
    
    Rule("M007", "MEDIUM", "Anti-Analysis",
         "Проверка на отладчик и песочницу",
         "Плагин проверяет окружение на признаки анализа",
         [r'Debugger\.IsAttached', r'\.Contains\s*\(\s*"sandbox"'],
         ["//"]),
    
    Rule("M008", "MEDIUM", "Anti-Analysis",
         "Time Bomb - отложенное выполнение",
         "Плагин активирует функциональность после определённой даты",
         [r'DateTime\.Now\s*[<>]', r'new\s+DateTime\s*\(\s*\d{4}'],
         ["//", "config"]),
    
    Rule("M009", "MEDIUM", "Steganography",
         "Чтение собственного исходного кода",
         "Плагин читает свой собственный .cs файл",
         [r'File\.ReadAllText\s*\([^)]*\.cs'],
         ["//", "config"]),
    
    Rule("M010", "MEDIUM", "Suspicious",
         "Математическое вычисление SteamID",
         "SteamID вычисляется через математические операции",
         [r'7656119\d+UL\s*[+\-*/]'],
         ["//"]),
    
    Rule("M011", "MEDIUM", "Suspicious",
         "Полиморфное выполнение",
         "Плагин случайно выбирает один из методов выполнения",
         [r'Environment\.TickCount\s*%'],
         ["//"]),
    
    Rule("M012", "MEDIUM", "Suspicious",
         "Создание файла автозагрузки плагина",
         "Плагин модифицирует autoload.txt",
         [r'autoload\.txt'],
         ["//"]),
    
    # Low severity threats
    Rule("L001", "LOW", "Network",
         "HTTP-запросы к внешним сервисам",
         "Плагин делает HTTP-запросы",
         [r'webrequest\.Enqueue\s*\('],
         ["//"]),
    
    Rule("L002", "LOW", "Suspicious",
         "Запрос/изменение ConVar",
         "Плагин читает или изменяет серверные переменные",
         [r'ConVar\.\w+\.', r'ConsoleSystem\.Run\s*\('],
         ["//"]),
    
    Rule("L003", "LOW", "Suspicious",
         "Доступ к PlayerToken / auth-данным",
         "Плагин обращается к токенам аутентификации игроков",
         [r'player\.net\.connection\.token', r'connection\.token'],
         ["//"]),
    
    Rule("L004", "LOW", "Steganography",
         "Использование невидимых Unicode символов",
         "В коде обнаружены zero-width Unicode символы",
         [r'[\u200B-\u200F]'],
         ["//"]),
    
    Rule("L005", "LOW", "Suspicious",
         "Использование StackTrace",
         "Плагин анализирует стек вызовов",
         [r'new\s+StackTrace\s*\('],
         ["//", "error"]),
    
    Rule("L006", "LOW", "Suspicious",
         "Вредоносная логика в обработчике исключений",
         "Подозрительный код в catch-блоке",
         [r'catch\s*\([^)]*\)\s*\{[^}]*(ConsoleSystem|Process\.Start)'],
         ["//", "log"]),
    
    # Informational findings
    Rule("I001", "INFO", "Info",
         "Использование Timer/InvokeRepeating",
         "Плагин использует повторяющиеся таймеры",
         [r'timer\.Repeat\s*\(', r'InvokeRepeating\s*\('],
         ["//"]),
]


# Scanning Engine

def scan_file(filepath: str) -> List[Finding]:
    """Scans a file and returns list of security findings"""
    findings: List[Finding] = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for rule in RULES:
        compiled = [re.compile(p, re.IGNORECASE) for p in rule.patterns]
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            
            for pat in compiled:
                m = pat.search(line)
                if m:
                    is_fp = any(hint.lower() in line.lower()
                               for hint in rule.false_positive_hints
                               if hint not in ("//",))
                    if not is_fp:
                        findings.append(Finding(
                            rule=rule,
                            line_no=lineno,
                            line_text=line.rstrip(),
                            match_text=m.group(0),
                            filepath=filepath
                        ))
                    break
    return findings

def get_context(filepath: str, line_no: int, radius: int = 4) -> str:
    """Retrieves code context around specified line"""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line_no - 1 - radius)
        end = min(len(lines), line_no + radius)
        result = []
        for i, ln in enumerate(lines[start:end], start=start + 1):
            marker = ">>>" if i == line_no else "   "
            result.append(f"{marker} {i:4}: {ln.rstrip()}")
        return "\n".join(result)
    except Exception:
        return ""

def export_txt(findings: List[Finding], filepath: str):
    """Exports findings to TXT format"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"=== {APP_NAME} v{APP_VERSION} ===\n")
        f.write(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Всего проблем: {len(findings)}\n\n")
        
        for finding in findings:
            f.write(f"[{finding.rule.severity}] {finding.rule.id}\n")
            f.write(f"Файл: {Path(finding.filepath).name}\n")
            f.write(f"Строка: {finding.line_no}\n")
            f.write(f"Название: {finding.rule.title}\n")
            f.write(f"Код: {finding.line_text}\n")
            f.write(f"Совпадение: {finding.match_text}\n")
            f.write(f"\n{'-'*60}\n\n")

def export_json(findings: List[Finding], filepath: str):
    """Exports findings to JSON format"""
    data = {
        "scan_date": datetime.now().isoformat(),
        "scanner_version": APP_VERSION,
        "total_findings": len(findings),
        "findings": []
    }
    
    for finding in findings:
        data["findings"].append({
            "severity": finding.rule.severity,
            "id": finding.rule.id,
            "category": finding.rule.category,
            "title": finding.rule.title,
            "file": Path(finding.filepath).name,
            "line": finding.line_no,
            "code": finding.line_text,
            "match": finding.match_text
        })
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def export_html(findings: List[Finding], filepath: str):
    """Exports findings to HTML format"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{APP_NAME} - Отчёт</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 20px; }}
        h1 {{ color: #7ec8e3; }}
        .finding {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid; }}
        .critical {{ border-color: #ff2020; }}
        .high {{ border-color: #ff7700; }}
        .medium {{ border-color: #ffcc00; }}
        .low {{ border-color: #44aaff; }}
        .info {{ border-color: #aaaaaa; }}
        .severity {{ font-weight: bold; padding: 4px 8px; border-radius: 4px; }}
        .critical-badge {{ background: #ff2020; color: white; }}
        .high-badge {{ background: #ff7700; color: white; }}
        .medium-badge {{ background: #ffcc00; color: black; }}
        .low-badge {{ background: #44aaff; color: white; }}
        .info-badge {{ background: #aaaaaa; color: white; }}
        code {{ background: #0a1929; padding: 2px 6px; border-radius: 4px; color: #f8c537; }}
        .meta {{ color: #888; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>🛡️ {APP_NAME} v{APP_VERSION}</h1>
    <p class="meta">Дата сканирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p class="meta">Всего проблем: {len(findings)}</p>
    <hr>
"""
    
    for finding in findings:
        sev_class = finding.rule.severity.lower()
        html += f"""
    <div class="finding {sev_class}">
        <span class="severity {sev_class}-badge">{finding.rule.severity}</span>
        <strong>{finding.rule.id}: {finding.rule.title}</strong>
        <p>{finding.rule.description}</p>
        <p class="meta">Файл: {Path(finding.filepath).name} | Строка: {finding.line_no}</p>
        <code>{finding.line_text}</code>
    </div>
"""
    
    html += """
</body>
</html>"""
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)


# Flet GUI Application

def main(page: ft.Page):
    page.title = f"{APP_NAME} v{APP_VERSION}"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.window_width = 1400
    page.window_height = 900
    page.window_min_width = 1000
    page.window_min_height = 700
    
    # Application state
    findings: List[Finding] = []
    selected_finding: Finding = None
    selected_index: int = -1
    
    # Filter references
    filter_critical = ft.Ref[ft.Checkbox]()
    filter_high = ft.Ref[ft.Checkbox]()
    filter_medium = ft.Ref[ft.Checkbox]()
    filter_low = ft.Ref[ft.Checkbox]()
    filter_info = ft.Ref[ft.Checkbox]()
    
    # UI component references
    file_path = ft.Ref[ft.TextField]()
    findings_list = ft.Ref[ft.ListView]()
    detail_panel = ft.Ref[ft.Column]()
    status_text = ft.Ref[ft.Text]()
    stats_text = ft.Ref[ft.Text]()
    progress_bar = ft.Ref[ft.ProgressBar]()
    
    def pick_file(e):
        def on_result(e: ft.FilePickerResultEvent):
            if e.files:
                file_path.current.value = e.files[0].path
                page.update()
        
        file_picker = ft.FilePicker(on_result=on_result)
        page.overlay.append(file_picker)
        page.update()
        file_picker.pick_files(
            allowed_extensions=["cs"],
            dialog_title="Выберите плагин (.cs)"
        )
    
    def pick_folder(e):
        def on_result(e: ft.FilePickerResultEvent):
            if e.path:
                file_path.current.value = e.path
                page.update()
        
        folder_picker = ft.FilePicker(on_result=on_result)
        page.overlay.append(folder_picker)
        page.update()
        folder_picker.get_directory_path(dialog_title="Выберите папку")
    
    def start_scan(e):
        nonlocal findings, selected_index
        path = file_path.current.value
        if not path:
            page.snack_bar = ft.SnackBar(ft.Text("Укажите файл или папку!"), bgcolor=ft.colors.RED_400)
            page.snack_bar.open = True
            page.update()
            return
        
        progress_bar.current.visible = True
        status_text.current.value = "Сканирование..."
        selected_index = -1
        page.update()
        
        findings.clear()
        p = Path(path)
        
        if p.is_file():
            findings.extend(scan_file(str(p)))
        elif p.is_dir():
            files = list(p.rglob("*.cs"))
            for file in files:
                findings.extend(scan_file(str(file)))
        
        findings.sort(key=lambda f: (
            -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[f.rule.severity],
            f.filepath,
            f.line_no
        ))
        
        progress_bar.current.visible = False
        update_findings_list()
        update_stats()
        
        if findings:
            status_text.current.value = f"✅ Сканирование завершено. Найдено {len(findings)} проблем."
        else:
            status_text.current.value = "✅ Подозрительный код не обнаружен."
        
        page.update()
    
    def update_findings_list():
        findings_list.current.controls.clear()
        filtered = [f for f in findings if should_show_finding(f)]
        
        for idx, finding in enumerate(filtered):
            def make_click_handler(f, index):
                def handler(e):
                    nonlocal selected_index
                    selected_index = index
                    show_detail(f)
                    update_findings_list()
                return handler
            
            is_selected = (idx == selected_index)
            
            findings_list.current.controls.append(
                ft.Container(
                    content=ft.Row([
                        ft.Container(
                            content=ft.Text(SEVERITY_ICON[finding.rule.severity], size=20),
                            width=40,
                            alignment=ft.alignment.center,
                        ),
                        ft.Column([
                            ft.Text(
                                f"{finding.rule.id}: {finding.rule.title}", 
                                weight=ft.FontWeight.BOLD,
                                size=14,
                            ),
                            ft.Text(
                                f"{Path(finding.filepath).name} | Строка {finding.line_no}",
                                size=12,
                                color=ft.colors.GREY_400,
                            ),
                        ], spacing=2, expand=True),
                        ft.Container(
                            content=ft.Text(
                                finding.rule.severity, 
                                size=10, 
                                weight=ft.FontWeight.BOLD,
                                color=ft.colors.WHITE,
                            ),
                            bgcolor=SEVERITY_COLOR[finding.rule.severity],
                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                            border_radius=4,
                        ),
                    ], spacing=10),
                    padding=10,
                    border=ft.border.only(bottom=ft.BorderSide(1, ft.colors.OUTLINE)),
                    bgcolor=ft.colors.BLUE_900 if is_selected else None,
                    on_click=make_click_handler(finding, idx),
                    ink=True,
                    border_radius=4,
                )
            )
        
        page.update()
    
    def should_show_finding(finding: Finding) -> bool:
        sev = finding.rule.severity
        if sev == "CRITICAL" and not filter_critical.current.value:
            return False
        if sev == "HIGH" and not filter_high.current.value:
            return False
        if sev == "MEDIUM" and not filter_medium.current.value:
            return False
        if sev == "LOW" and not filter_low.current.value:
            return False
        if sev == "INFO" and not filter_info.current.value:
            return False
        return True
    
    def show_detail(finding: Finding):
        nonlocal selected_finding
        selected_finding = finding
        context = get_context(finding.filepath, finding.line_no)
        detail_panel.current.controls.clear()
        
        new_content = ft.Column([
            ft.Text(f"{SEVERITY_ICON[finding.rule.severity]} {finding.rule.title}",
                   size=20, weight=ft.FontWeight.BOLD),
            ft.Divider(height=1, color=ft.colors.OUTLINE),
            
            ft.Container(
                content=ft.Text(finding.rule.severity, weight=ft.FontWeight.BOLD, color=ft.colors.WHITE, size=14),
                bgcolor=SEVERITY_COLOR[finding.rule.severity],
                padding=10,
                border_radius=8,
                alignment=ft.alignment.center,
            ),
            
            ft.Text("📁 Где нашли", size=16, weight=ft.FontWeight.BOLD, color=ft.colors.BLUE_200),
            ft.Text(f"Файл: {Path(finding.filepath).name}", size=14),
            ft.Text(f"Строка: {finding.line_no}", size=14),
            ft.Text(f"Категория: {finding.rule.category}", size=14),
            ft.Text(f"Правило: {finding.rule.id}", size=14),
            
            ft.Divider(height=10),
            
            ft.Text("🔎 Что именно нашло", size=16, weight=ft.FontWeight.BOLD, color=ft.colors.BLUE_200),
            ft.Container(
                content=ft.Column([
                    ft.Text(f"Строка {finding.line_no}:", color=ft.colors.GREY_400, size=12),
                    ft.TextField(
                        value=finding.line_text,
                        multiline=True,
                        read_only=True,
                        border_color=ft.colors.TRANSPARENT,
                        text_size=13,
                    ),
                    ft.Divider(height=5),
                    ft.Text(f"Сработало на:", color=ft.colors.GREY_400, size=12),
                    ft.TextField(
                        value=finding.match_text,
                        multiline=True,
                        read_only=True,
                        border_color=ft.colors.TRANSPARENT,
                        text_size=13,
                        color=ft.colors.RED_300,
                    ),
                ], spacing=5),
                bgcolor=ft.colors.with_opacity(0.3, ft.colors.SURFACE_VARIANT),
                padding=10,
                border_radius=8
            ),
            
            ft.Divider(height=10),
            
            ft.Text("📄 Контекст кода", size=16, weight=ft.FontWeight.BOLD, color=ft.colors.BLUE_200),
            ft.Container(
                content=ft.TextField(
                    value=context if context else "Контекст недоступен",
                    multiline=True,
                    read_only=True,
                    border_color=ft.colors.TRANSPARENT,
                    text_size=12,
                ),
                bgcolor=ft.colors.with_opacity(0.3, ft.colors.SURFACE_VARIANT),
                padding=10,
                border_radius=8,
                height=200,
            ),
            
            ft.Divider(height=10),
            
            ft.Text("⚠️ Чем это опасно", size=16, weight=ft.FontWeight.BOLD, color=ft.colors.BLUE_200),
            ft.Text(finding.rule.description, color=ft.colors.AMBER_200, size=14),
            
            ft.Divider(height=10),
            
            ft.Row([
                ft.ElevatedButton(
                    "📋 Копировать код", 
                    on_click=lambda e: copy_code(),
                    bgcolor=ft.colors.BLUE_700,
                ),
                ft.ElevatedButton(
                    "📋 Копировать контекст", 
                    on_click=lambda e: copy_context(),
                    bgcolor=ft.colors.BLUE_700,
                ),
            ], spacing=10),
        ], spacing=8)
        
        detail_panel.current.controls.append(new_content)
        detail_panel.current.update()
        page.update()
    
    def copy_code():
        if selected_finding:
            page.set_clipboard(selected_finding.line_text)
            page.snack_bar = ft.SnackBar(ft.Text("✅ Код скопирован!"), bgcolor=ft.colors.GREEN_400)
            page.snack_bar.open = True
            page.update()
    
    def copy_context():
        if selected_finding:
            context = get_context(selected_finding.filepath, selected_finding.line_no)
            page.set_clipboard(context)
            page.snack_bar = ft.SnackBar(ft.Text("✅ Контекст скопирован!"), bgcolor=ft.colors.GREEN_400)
            page.snack_bar.open = True
            page.update()
    
    def update_stats():
        if not findings:
            stats_text.current.value = "Нет данных"
            return
        
        critical = sum(1 for f in findings if f.rule.severity == "CRITICAL")
        high = sum(1 for f in findings if f.rule.severity == "HIGH")
        medium = sum(1 for f in findings if f.rule.severity == "MEDIUM")
        low = sum(1 for f in findings if f.rule.severity == "LOW")
        info = sum(1 for f in findings if f.rule.severity == "INFO")
        
        stats_text.current.value = (
            f"Всего: {len(findings)} | "
            f"🔴 {critical} | 🟠 {high} | 🟡 {medium} | 🔵 {low} | ⚪ {info}"
        )
    
    def on_filter_change(e):
        update_findings_list()
        page.update()
    
    def export_report(e, format_type):
        if not findings:
            page.snack_bar = ft.SnackBar(ft.Text("Нет данных для экспорта!"), bgcolor=ft.colors.RED_400)
            page.snack_bar.open = True
            page.update()
            return
        
        def on_result(e: ft.FilePickerResultEvent):
            if e.path:
                try:
                    if format_type == "txt":
                        export_txt(findings, e.path)
                    elif format_type == "json":
                        export_json(findings, e.path)
                    elif format_type == "html":
                        export_html(findings, e.path)
                    
                    page.snack_bar = ft.SnackBar(ft.Text(f"✅ Отчёт сохранён: {e.path}"), bgcolor=ft.colors.GREEN_400)
                    page.snack_bar.open = True
                    page.update()
                except Exception as ex:
                    page.snack_bar = ft.SnackBar(ft.Text(f"❌ Ошибка: {ex}"), bgcolor=ft.colors.RED_400)
                    page.snack_bar.open = True
                    page.update()
        
        save_picker = ft.FilePicker(on_result=on_result)
        page.overlay.append(save_picker)
        page.update()
        
        ext = {"txt": "txt", "json": "json", "html": "html"}[format_type]
        save_picker.save_file(
            dialog_title=f"Сохранить отчёт ({format_type.upper()})",
            file_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        )

    
    # Build UI
    page.add(
        ft.Container(
            content=ft.Column([
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.icons.SECURITY, size=40, color=ft.colors.BLUE_400),
                        ft.Column([
                            ft.Text(APP_NAME, size=24, weight=ft.FontWeight.BOLD),
                            ft.Text(f"v{APP_VERSION} | by {APP_AUTHOR}", size=12, color=ft.colors.GREY_400),
                        ], spacing=0),
                    ]),
                    bgcolor=ft.colors.SURFACE_VARIANT,
                    padding=20,
                ),
                
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.TextField(
                                ref=file_path,
                                label="Файл или папка",
                                hint_text="Выберите .cs файл или папку с плагинами",
                                expand=True,
                                border_color=ft.colors.BLUE_400,
                            ),
                            ft.IconButton(
                                icon=ft.icons.INSERT_DRIVE_FILE,
                                tooltip="Выбрать файл",
                                on_click=pick_file,
                                bgcolor=ft.colors.BLUE_700,
                            ),
                            ft.IconButton(
                                icon=ft.icons.FOLDER_OPEN,
                                tooltip="Выбрать папку",
                                on_click=pick_folder,
                                bgcolor=ft.colors.BLUE_700,
                            ),
                            ft.ElevatedButton(
                                "🔍 СКАНИРОВАТЬ",
                                on_click=start_scan,
                                bgcolor=ft.colors.GREEN_700,
                                color=ft.colors.WHITE,
                                height=56,
                            ),
                        ]),
                        
                        ft.Row([
                            ft.Text("Показать:", weight=ft.FontWeight.BOLD),
                            ft.Checkbox(ref=filter_critical, label="🔴 CRITICAL", value=True, on_change=on_filter_change),
                            ft.Checkbox(ref=filter_high, label="🟠 HIGH", value=True, on_change=on_filter_change),
                            ft.Checkbox(ref=filter_medium, label="🟡 MEDIUM", value=True, on_change=on_filter_change),
                            ft.Checkbox(ref=filter_low, label="🔵 LOW", value=True, on_change=on_filter_change),
                            ft.Checkbox(ref=filter_info, label="⚪ INFO", value=True, on_change=on_filter_change),
                        ], wrap=True),
                        
                        ft.ProgressBar(ref=progress_bar, visible=False),
                        ft.Text(ref=status_text, value="Готов к сканированию", color=ft.colors.GREY_400),
                    ]),
                    padding=20,
                ),
                
                ft.Container(
                    content=ft.Row([
                        ft.Container(
                            content=ft.Column([
                                ft.Text("Найденные проблемы", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ListView(
                                    ref=findings_list,
                                    expand=True,
                                    spacing=0,
                                    padding=0,
                                ),
                            ]),
                            bgcolor=ft.colors.SURFACE_VARIANT,
                            padding=10,
                            border_radius=8,
                            expand=2,
                        ),
                        
                        ft.Container(
                            content=ft.Column([
                                ft.Text("Детали находки", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.Column(
                                    ref=detail_panel,
                                    scroll=ft.ScrollMode.AUTO,
                                    expand=True,
                                    controls=[
                                        ft.Container(
                                            content=ft.Column([
                                                ft.Icon(ft.icons.INFO_OUTLINE, size=64, color=ft.colors.GREY_600),
                                                ft.Text("Выберите проблему из списка", 
                                                       size=16, 
                                                       color=ft.colors.GREY_600,
                                                       text_align=ft.TextAlign.CENTER),
                                                ft.Text("Кликните на любую находку слева,\nчтобы увидеть подробности", 
                                                       size=12, 
                                                       color=ft.colors.GREY_700,
                                                       text_align=ft.TextAlign.CENTER),
                                            ], 
                                            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                            spacing=10),
                                            padding=50,
                                            alignment=ft.alignment.center,
                                        )
                                    ],
                                ),
                            ], expand=True),
                            bgcolor=ft.colors.SURFACE_VARIANT,
                            padding=10,
                            border_radius=8,
                            expand=3,
                        ),
                    ], expand=True),
                    expand=True,
                    padding=20,
                ),
                
                ft.Container(
                    content=ft.Row([
                        ft.Text(ref=stats_text, value="Нет данных", expand=True),
                        ft.PopupMenuButton(
                            icon=ft.icons.DOWNLOAD,
                            tooltip="Экспорт отчёта",
                            items=[
                                ft.PopupMenuItem(text="📄 Экспорт в TXT", on_click=lambda e: export_report(e, "txt")),
                                ft.PopupMenuItem(text="📊 Экспорт в JSON", on_click=lambda e: export_report(e, "json")),
                                ft.PopupMenuItem(text="🌐 Экспорт в HTML", on_click=lambda e: export_report(e, "html")),
                            ],
                        ),
                    ]),
                    bgcolor=ft.colors.SURFACE_VARIANT,
                    padding=10,
                ),
            ], spacing=0, expand=True),
            expand=True,
        )
    )

if __name__ == "__main__":
    ft.app(target=main)
