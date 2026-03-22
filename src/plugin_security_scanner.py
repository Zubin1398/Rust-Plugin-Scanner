"""
Rust Oxide Plugin Security Scanner
Сканер безопасности плагинов для игрового сервера Rust (Oxide/uMod)

Автор:   MMZ4
Версия:  1.0.0

Ищет потенциально опасный код:
- Кражу данных (IP, SteamID, токены) через внешние запросы
- Выдачу прав администратора через консольные команды
- Выполнение shell-команд на сервере
- Динамическое выполнение кода
- Жёстко прописанные ключи/пароли
- SQL-инъекции
- Вредоносные Harmony-патчи
"""

APP_NAME    = "Rust Plugin Security Scanner"
APP_AUTHOR  = "MMZ4"
APP_VERSION = "1.0.0"

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import re
import os
import threading
from dataclasses import dataclass, field
from typing import List, Tuple
from pathlib import Path


# ---------------------------------------------------------------------------
# Правила сканирования
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    title: str
    description: str
    patterns: List[str]
    false_positive_hints: List[str] = field(default_factory=list)


SEVERITY_COLOR = {
    "CRITICAL": "#ff2020",
    "HIGH":     "#ff7700",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#aaaaaa",
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

RULES: List[Rule] = [

    # ── КРИТИЧЕСКИЕ ──────────────────────────────────────────────────────────

    Rule(
        id="C001",
        severity="CRITICAL",
        category="Admin Escalation",
        title="Выдача прав администратора через ConsoleSystem",
        description=(
            "Плагин выполняет команду ownerid/moderatorid через ConsoleSystem.Run или server.command. "
            "Это позволяет автору плагина выдать себе права на вашем сервере."
        ),
        patterns=[
            r'ConsoleSystem\.Run\s*\([^)]*"ownerid',
            r'ConsoleSystem\.Run\s*\([^)]*"moderatorid',
            r'rust\.RunServerCommand\s*\([^)]*"ownerid',
            r'rust\.RunServerCommand\s*\([^)]*"moderatorid',
            r'Server\.Command\s*\([^)]*"ownerid',
            r'Server\.Command\s*\([^)]*"moderatorid',
            r'"ownerid\s+\d{17}',
            r'"moderatorid\s+\d{17}',
        ],
        false_positive_hints=["//", "/*", "example", "sample"],
    ),

    Rule(
        id="C002",
        severity="CRITICAL",
        category="Admin Escalation",
        title="Прямое добавление в группу oxide.admin",
        description=(
            "Плагин программно добавляет игроков в группу oxide.admin или выдаёт права через permission.Grant."
        ),
        patterns=[
            r'permission\.AddUserGroup\s*\([^)]*"oxide\.admin"',
            r'permission\.GrantUserPermission\s*\([^)]*"',
            r'permission\.AddUserGroup\s*\([^)]*admin',
            r'ServerUsers\.Set\s*\([^,]+,\s*ServerUsers\.UserGroup\.Owner',
            r'ServerUsers\.Set\s*\([^,]+,\s*ServerUsers\.UserGroup\.Moderator',
        ],
        false_positive_hints=["//", "hasPermission", "UserHasPermission"],
    ),

    Rule(
        id="C003",
        severity="CRITICAL",
        category="Remote Code Execution",
        title="Запуск системных процессов / shell-команд",
        description=(
            "Плагин создаёт системный процесс (cmd.exe, powershell, bash). "
            "Это может использоваться для выполнения произвольных команд на сервере, "
            "удаления файлов, кражи данных или установки backdoor."
        ),
        patterns=[
            r'System\.Diagnostics\.Process',
            r'ProcessStartInfo',
            r'Process\.Start\s*\(',
            r'new\s+Process\s*\(',
            r'"cmd\.exe"',
            r'"powershell"',
            r'"/bin/bash"',
            r'"/bin/sh"',
            r'shell32\.dll',
        ],
        false_positive_hints=["//"],
    ),

    Rule(
        id="C004",
        severity="CRITICAL",
        category="Remote Code Execution",
        title="Динамическая компиляция и выполнение кода",
        description=(
            "Плагин компилирует и выполняет код в рантайме. "
            "Позволяет выполнить любой код, переданный извне (с сервера автора)."
        ),
        patterns=[
            r'CSharpCodeProvider',
            r'CompileAssemblyFromSource',
            r'Assembly\.Load\s*\(',
            r'Assembly\.LoadFrom\s*\(',
            r'Assembly\.LoadFile\s*\(',
            r'Activator\.CreateInstance.*Assembly',
            r'Microsoft\.CodeAnalysis',
            r'\.Emit\s*\(',
            r'RoslynCompiler',
            r'ScriptEngine',
        ],
        false_positive_hints=["//", "Activator.CreateInstance<T>()"],
    ),

    Rule(
        id="C005",
        severity="CRITICAL",
        category="Data Exfiltration",
        title="Отправка данных на жёстко прописанный URL (не Discord/Steam)",
        description=(
            "Плагин отправляет HTTP-запросы на URL, который не является официальным Steam, "
            "Discord или Oxide API. Потенциальная утечка данных сервера/игроков."
        ),
        patterns=[
            r'WebClient\s*\(',
            r'HttpClient\s*\(',
            r'new\s+WebRequest',
            r'HttpWebRequest\.Create',
            r'TcpClient\s*\(',
            r'UdpClient\s*\(',
            r'new\s+Socket\s*\(',
            r'webrequest\.Enqueue\s*\(["\']https?://(?!api\.steampowered|discord\.com|discordapp\.com|umod\.org)',
        ],
        false_positive_hints=["//", "api.steampowered", "discord", "umod.org"],
    ),

    # ── ВЫСОКИЕ ──────────────────────────────────────────────────────────────

    Rule(
        id="H001",
        severity="HIGH",
        category="Data Exfiltration",
        title="Отправка SteamID / IP-адресов на внешний сервер",
        description=(
            "Плагин собирает SteamID или IP-адреса игроков и отправляет их на внешний URL. "
            "Может использоваться для слежки за игроками или продажи базы данных."
        ),
        patterns=[
            r'player\.UserIDString.*webrequest',
            r'player\.net\.connection\.ipaddress.*webrequest',
            r'userID.*WebClient',
            r'\.ipaddress.*HttpClient',
            r'ip-api\.com',
            r'ipinfo\.io',
            r'ipgeolocation\.io',
            r'freegeoip\.net',
        ],
        false_positive_hints=["//", "discord", "ban"],
    ),

    Rule(
        id="H002",
        severity="HIGH",
        category="File System",
        title="Запись/удаление произвольных файлов на сервере",
        description=(
            "Плагин пишет или удаляет файлы за пределами стандартных директорий Oxide. "
            "Может удалить важные файлы сервера или создать backdoor-скрипты."
        ),
        patterns=[
            r'File\.Delete\s*\(',
            r'File\.WriteAllText\s*\(',
            r'File\.WriteAllBytes\s*\(',
            r'Directory\.Delete\s*\(',
            r'StreamWriter\s*\([^)]*\)',
            r'File\.Move\s*\(',
            r'File\.Copy\s*\(',
        ],
        false_positive_hints=["//", "oxide/data", "config/", "Interface.Oxide"],
    ),

    Rule(
        id="H003",
        severity="HIGH",
        category="Obfuscation",
        title="Base64-декодирование строк в рантайме",
        description=(
            "Плагин декодирует строки из Base64 во время выполнения. "
            "Классическая техника скрытия вредоносного кода от ревью."
        ),
        patterns=[
            r'Convert\.FromBase64String\s*\(',
            r'Convert\.ToBase64String\s*\(',
            r'Encoding\.\w+\.GetString\s*\(Convert\.FromBase64',
        ],
        false_positive_hints=["//", "ImageLibrary", "Decrypt", "EncryptDecrypt"],
    ),

    Rule(
        id="H004",
        severity="HIGH",
        category="Harmony Patch",
        title="Потенциально опасный Harmony-патч",
        description=(
            "Плагин использует Harmony для патча игровых методов. "
            "Патчи могут перехватывать аутентификацию, обход античита или изменять поведение сервера."
        ),
        patterns=[
            r'\[HarmonyPatch\(',
            r'harmony\.Patch\s*\(',
            r'HarmonyMethod\s*\(',
            r'new\s+Harmony\s*\(',
        ],
        false_positive_hints=["//"],
    ),

    Rule(
        id="H005",
        severity="HIGH",
        category="Credentials",
        title="Жёстко прописанные SteamID (возможная backdoor-учётка)",
        description=(
            "В коде найдены жёстко прописанные SteamID64. "
            "Автор плагина мог добавить свой SteamID для автоматической выдачи прав."
        ),
        patterns=[
            r'(?<!\w)7656119\d{10}(?!\d)',   # SteamID64 формат
        ],
        false_positive_hints=["//", "example", "test", "sample", "0"],
    ),

    # ── СРЕДНИЕ ──────────────────────────────────────────────────────────────

    Rule(
        id="M001",
        severity="MEDIUM",
        category="SQL Injection",
        title="SQL-запрос с интерполяцией строк (возможная SQL-инъекция)",
        description=(
            "SQL-запрос формируется через конкатенацию или интерполяцию строк без параметризации. "
            "Позволяет игроку с нужным ником/причиной бана выполнить произвольный SQL."
        ),
        patterns=[
            r'Sql\.Builder\.Append\s*\(\s*\$"[^"]*\{',
            r'Sql\.Builder\.Append\s*\(\s*"[^"]*"\s*\+',
            r'"SELECT.*WHERE.*\+\s*\w',
            r'"INSERT INTO.*VALUES.*\+\s*\w',
            r'"UPDATE.*SET.*\+\s*\w',
            r'"DELETE FROM.*WHERE.*\+\s*\w',
        ],
        false_positive_hints=["//", "@0", "@1"],
    ),

    Rule(
        id="M002",
        severity="MEDIUM",
        category="Reflection",
        title="Использование рефлексии для вызова методов",
        description=(
            "Плагин использует рефлексию для динамического вызова методов. "
            "Может использоваться для обхода проверок доступа или вызова приватных методов."
        ),
        patterns=[
            r'Type\.GetMethod\s*\(',
            r'MethodInfo\.Invoke\s*\(',
            r'\.GetField\s*\([^)]*BindingFlags\.(NonPublic|Static)',
            r'\.GetProperty\s*\([^)]*BindingFlags\.NonPublic',
            r'Activator\.CreateInstance\s*\(',
        ],
        false_positive_hints=["//", "GetProperty(propertyName)"],
    ),

    Rule(
        id="M003",
        severity="MEDIUM",
        category="Network",
        title="Отправка данных через Discord Webhook",
        description=(
            "Плагин отправляет данные на Discord webhook. "
            "Проверьте что webhook URL указан только в конфиге, а не прошит в коде."
        ),
        patterns=[
            r'"https://discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"',
            r'DiscordWebhook.*=.*"https://',
            r'webhookUrl\s*=\s*"https://discord',
        ],
        false_positive_hints=["//", "config.", "_config.", "Config["],
    ),

    Rule(
        id="M004",
        severity="MEDIUM",
        category="Data Exfiltration",
        title="Hardcoded API-ключ в коде",
        description=(
            "В коде найден жёстко прописанный API-ключ или токен. "
            "Это может быть ключ автора плагина, которым он получает данные от Steam/других сервисов."
        ),
        patterns=[
            r'apiKey\s*=\s*"[A-Za-z0-9]{20,}"',
            r'APIKey\s*=\s*"[A-Za-z0-9]{20,}"',
            r'api_key\s*=\s*"[A-Za-z0-9]{20,}"',
            r'token\s*=\s*"[A-Za-z0-9]{30,}"',
            r'secret\s*=\s*"[A-Za-z0-9]{20,}"',
            r'"key"\s*:\s*"[A-Za-z0-9]{30,}"',
        ],
        false_positive_hints=["//", "SteamAPIKey", "config.", "_config."],
    ),

    Rule(
        id="M005",
        severity="MEDIUM",
        category="Obfuscation",
        title="Шифрование/дешифрование с жёстко прописанным ключом",
        description=(
            "Плагин использует симметричное шифрование (AES/DES) с ключом, "
            "прошитым прямо в коде. Может скрывать зашифрованный payload."
        ),
        patterns=[
            r'Aes\.Create\s*\(',
            r'AesManaged\s*\(',
            r'RijndaelManaged\s*\(',
            r'DESCryptoServiceProvider\s*\(',
            r'TripleDESCryptoServiceProvider\s*\(',
            r'aes\.Key\s*=\s*Convert\.FromBase64String',
        ],
        false_positive_hints=["//"],
    ),

    # ── НИЗКИЕ ───────────────────────────────────────────────────────────────

    Rule(
        id="L001",
        severity="LOW",
        category="Network",
        title="HTTP-запросы к внешним сервисам",
        description=(
            "Плагин делает HTTP-запросы. Проверьте все URL — они должны быть из конфига, "
            "а не прошиты в коде."
        ),
        patterns=[
            r'webrequest\.Enqueue\s*\(',
            r'UnityWebRequest\.\w+\s*\(',
        ],
        false_positive_hints=["//"],
    ),

    Rule(
        id="L002",
        severity="LOW",
        category="Suspicious",
        title="Запрос/изменение ConVar (серверных переменных)",
        description=(
            "Плагин читает или изменяет серверные переменные через ConVar. "
            "Некоторые ConVar могут влиять на безопасность сервера."
        ),
        patterns=[
            r'ConVar\.\w+\.',
            r'ConsoleSystem\.Run\s*\(',
            r'rust\.RunServerCommand\s*\(',
        ],
        false_positive_hints=["//"],
    ),

    Rule(
        id="L003",
        severity="LOW",
        category="Suspicious",
        title="Доступ к PlayerToken / auth-данным",
        description=(
            "Плагин обращается к токенам аутентификации игроков. "
            "Утечка токенов позволяет похитить аккаунты."
        ),
        patterns=[
            r'player\.net\.connection\.token',
            r'player\.userToken',
            r'connection\.authLevel',
            r'connection\.token',
        ],
        false_positive_hints=["//"],
    ),

    # ── INFO ─────────────────────────────────────────────────────────────────

    Rule(
        id="I001",
        severity="INFO",
        category="Info",
        title="Использование Timer/InvokeRepeating",
        description=(
            "Плагин использует повторяющиеся таймеры. Само по себе безопасно, "
            "но стоит проверить что они делают."
        ),
        patterns=[
            r'timer\.Repeat\s*\(',
            r'InvokeRepeating\s*\(',
        ],
        false_positive_hints=["//"],
    ),
]


# ---------------------------------------------------------------------------
# Движок сканирования
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: Rule
    line_no: int
    line_text: str
    match_text: str


def scan_file(filepath: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return findings

    for rule in RULES:
        compiled = [re.compile(p, re.IGNORECASE) for p in rule.patterns]
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Пропускаем чистые комментарии
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            for pat in compiled:
                m = pat.search(line)
                if m:
                    # Проверяем false-positive hints
                    is_fp = any(hint.lower() in line.lower()
                                for hint in rule.false_positive_hints
                                if hint not in ("//",))
                    if not is_fp:
                        findings.append(Finding(
                            rule=rule,
                            line_no=lineno,
                            line_text=line.rstrip(),
                            match_text=m.group(0),
                        ))
                    break   # одно совпадение на правило на строку достаточно
    return findings


def severity_score(s: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"🛡️ {APP_NAME}  v{APP_VERSION}  |  by {APP_AUTHOR}")
        self.geometry("1200x780")
        self.minsize(900, 600)
        self.configure(bg="#1a1a2e")

        self._findings: List[Tuple[str, Finding]] = []   # (filepath, finding)
        self._scan_thread: threading.Thread | None = None

        self._build_ui()

    # ── About ────────────────────────────────────────────────────────────────

    def _show_about(self):
        win = tk.Toplevel(self)
        win.title("О программе")
        win.geometry("420x300")
        win.resizable(False, False)
        win.configure(bg="#16213e")
        win.grab_set()

        tk.Label(win, text="🛡️", font=("Segoe UI", 40),
                 bg="#16213e", fg="#e0e0e0").pack(pady=(20, 0))
        tk.Label(win, text=APP_NAME,
                 font=("Segoe UI", 14, "bold"),
                 bg="#16213e", fg="#e0e0e0").pack()
        tk.Label(win, text=f"Версия {APP_VERSION}",
                 font=("Segoe UI", 10),
                 bg="#16213e", fg="#888").pack(pady=(2, 0))

        sep = tk.Frame(win, bg="#333", height=1)
        sep.pack(fill="x", padx=30, pady=14)

        tk.Label(win,
                 text=(
                     f"Автор:       {APP_AUTHOR}\n"
                     "Назначение:  Проверка плагинов Rust (Oxide/uMod)\n"
                     "             на вредоносный и опасный код\n\n"
                     "Поддерживаемые форматы:  .cs"
                 ),
                 font=("Segoe UI", 10), bg="#16213e", fg="#aaa",
                 justify="left").pack(padx=30)

        tk.Button(win, text="Закрыть",
                  command=win.destroy,
                  bg="#533483", fg="white", relief="flat",
                  font=("Segoe UI", 10, "bold"),
                  cursor="hand2", padx=20, pady=6).pack(pady=18)

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self, bg="#16213e", pady=10)
        hdr.pack(fill="x")
        tk.Label(
            hdr, text=f"🛡️  {APP_NAME}",
            font=("Segoe UI", 18, "bold"), bg="#16213e", fg="#e0e0e0"
        ).pack(side="left", padx=20)
        tk.Label(
            hdr, text="Анализатор безопасности плагинов (Oxide / uMod)",
            font=("Segoe UI", 10), bg="#16213e", fg="#888"
        ).pack(side="left")
        # About кнопка справа
        tk.Button(
            hdr, text=f"ℹ️  v{APP_VERSION}  |  {APP_AUTHOR}",
            command=self._show_about,
            bg="#16213e", fg="#5588cc", relief="flat",
            font=("Segoe UI", 9), cursor="hand2",
            activebackground="#16213e", activeforeground="#88aaff",
            bd=0
        ).pack(side="right", padx=20)

        # ── File picker ──
        pick_frame = tk.Frame(self, bg="#1a1a2e", pady=8)
        pick_frame.pack(fill="x", padx=15)

        tk.Label(pick_frame, text="Файл или папка:", bg="#1a1a2e",
                 fg="#ccc", font=("Segoe UI", 10)).pack(side="left")

        self._path_var = tk.StringVar()
        path_entry = tk.Entry(pick_frame, textvariable=self._path_var,
                              bg="#0f3460", fg="#e0e0e0", insertbackground="white",
                              font=("Consolas", 10), width=70, relief="flat",
                              highlightthickness=1, highlightbackground="#444")
        path_entry.pack(side="left", padx=(8, 4), ipady=4)

        btn_style = dict(bg="#533483", fg="white", relief="flat",
                         font=("Segoe UI", 9, "bold"), cursor="hand2",
                         padx=10, pady=4)

        tk.Button(pick_frame, text="📄 Файл (.cs)",
                  command=self._pick_file, **btn_style).pack(side="left", padx=2)
        tk.Button(pick_frame, text="📁 Папка",
                  command=self._pick_dir, **btn_style).pack(side="left", padx=2)

        scan_btn = tk.Button(pick_frame, text="🔍  СКАНИРОВАТЬ",
                             command=self._start_scan,
                             bg="#e94560", fg="white", relief="flat",
                             font=("Segoe UI", 10, "bold"), cursor="hand2",
                             padx=16, pady=4)
        scan_btn.pack(side="left", padx=(12, 0))
        self._scan_btn = scan_btn

        # ── Severity filter ──
        filt_frame = tk.Frame(self, bg="#1a1a2e")
        filt_frame.pack(fill="x", padx=15, pady=(0, 4))

        tk.Label(filt_frame, text="Показать:", bg="#1a1a2e",
                 fg="#aaa", font=("Segoe UI", 9)).pack(side="left")

        self._sev_vars: dict[str, tk.BooleanVar] = {}
        for sev, color in SEVERITY_COLOR.items():
            var = tk.BooleanVar(value=True)
            self._sev_vars[sev] = var
            cb = tk.Checkbutton(
                filt_frame, text=f"{SEVERITY_ICON[sev]} {sev}",
                variable=var, command=self._apply_filter,
                bg="#1a1a2e", fg=color, selectcolor="#1a1a2e",
                activebackground="#1a1a2e", activeforeground=color,
                font=("Segoe UI", 9, "bold")
            )
            cb.pack(side="left", padx=6)

        # ── Progress ──
        self._progress_var = tk.StringVar(value="Готов к сканированию.")
        tk.Label(self, textvariable=self._progress_var,
                 bg="#1a1a2e", fg="#666", font=("Segoe UI", 9),
                 anchor="w").pack(fill="x", padx=15)

        # ── Main pane ──
        pane = tk.PanedWindow(self, orient="horizontal",
                              bg="#1a1a2e", sashwidth=5, sashpad=2)
        pane.pack(fill="both", expand=True, padx=10, pady=(4, 0))

        # Left: findings list
        left = tk.Frame(pane, bg="#0f3460")
        pane.add(left, minsize=380)

        tk.Label(left, text="Найденные проблемы",
                 bg="#16213e", fg="#ccc", font=("Segoe UI", 10, "bold"),
                 pady=6).pack(fill="x")

        cols = ("sev", "id", "file", "line", "title")
        self._tree = ttk.Treeview(left, columns=cols, show="headings",
                                  selectmode="browse")
        self._tree.heading("sev",   text="!")
        self._tree.heading("id",    text="ID")
        self._tree.heading("file",  text="Файл")
        self._tree.heading("line",  text="Стр")
        self._tree.heading("title", text="Название")

        self._tree.column("sev",  width=30,  stretch=False)
        self._tree.column("id",   width=52,  stretch=False)
        self._tree.column("file", width=160, stretch=True)
        self._tree.column("line", width=42,  stretch=False)
        self._tree.column("title",width=240, stretch=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background="#0f3460", foreground="#ddd",
                         rowheight=22, fieldbackground="#0f3460",
                         font=("Consolas", 9))
        style.configure("Treeview.Heading",
                         background="#16213e", foreground="#aaa",
                         font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#533483")])

        for sev, color in SEVERITY_COLOR.items():
            self._tree.tag_configure(sev, foreground=color)

        vsb = ttk.Scrollbar(left, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(left, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Right: detail panel
        right = tk.Frame(pane, bg="#16213e")
        pane.add(right, minsize=380)

        tk.Label(right, text="Детали находки",
                 bg="#16213e", fg="#ccc", font=("Segoe UI", 10, "bold"),
                 pady=6).pack(fill="x")

        # Detail text
        self._detail_text = scrolledtext.ScrolledText(
            right, bg="#16213e", fg="#e0e0e0", font=("Consolas", 10),
            wrap="word", state="disabled", relief="flat",
            padx=10, pady=8
        )
        self._detail_text.pack(fill="both", expand=True)

        # ── Теги стилей для панели деталей ──────────────────────────────────
        dt = self._detail_text

        # Заголовок находки
        dt.tag_configure("heading",
                         font=("Segoe UI", 12, "bold"), foreground="#ffffff")
        # Горизонтальный разделитель
        dt.tag_configure("sep",
                         foreground="#333344", font=("Consolas", 8))
        # Заголовки разделов (Где нашли / Что нашло / Чем опасно / Что делать)
        dt.tag_configure("section",
                         font=("Segoe UI", 10, "bold"), foreground="#7ec8e3",
                         spacing1=6, spacing3=2)
        # Подсказки серым мелким текстом
        dt.tag_configure("hint",
                         font=("Segoe UI", 9, "italic"), foreground="#666688")
        # Метки полей (Файл:, Строка: и т.д.)
        dt.tag_configure("label",
                         font=("Segoe UI", 9, "bold"), foreground="#8888aa")
        # Значения полей
        dt.tag_configure("value",
                         font=("Segoe UI", 9), foreground="#ccccdd")
        # Блок кода (жёлтый на тёмном фоне)
        dt.tag_configure("code",
                         font=("Consolas", 10), foreground="#f8c537",
                         background="#0a1929", lmargin1=10, lmargin2=10,
                         spacing1=2, spacing3=2)
        # Подсветка найденного совпадения
        dt.tag_configure("match",
                         font=("Consolas", 10, "bold"), foreground="#ff6b6b",
                         background="#1a0a0a")
        # Описание угрозы
        dt.tag_configure("desc",
                         font=("Segoe UI", 10), foreground="#aad4f5",
                         lmargin1=4, lmargin2=4, spacing1=2)
        # Рекомендация (что делать)
        dt.tag_configure("rec",
                         font=("Segoe UI", 10), foreground="#90ee90",
                         lmargin1=4, lmargin2=4, spacing1=1)
        # Полный путь к файлу
        dt.tag_configure("path",
                         font=("Consolas", 9), foreground="#556677")

        # Бейджи уровня опасности (цветной фон)
        BADGE_BG = {
            "CRITICAL": "#4a0000", "HIGH": "#3a2000",
            "MEDIUM":   "#2a2a00", "LOW":  "#001a3a", "INFO": "#1a1a1a",
        }
        for sev, color in SEVERITY_COLOR.items():
            dt.tag_configure(f"badge_{sev}",
                             font=("Segoe UI", 10, "bold"),
                             foreground=color, background=BADGE_BG.get(sev, "#111"),
                             relief="raised", borderwidth=1)
            # Оставляем и старый тег sev_ для совместимости
            dt.tag_configure(f"sev_{sev}",
                             foreground=color, font=("Segoe UI", 11, "bold"))

        # ── Bottom status bar ──
        status_bar = tk.Frame(self, bg="#16213e", pady=3)
        status_bar.pack(fill="x")
        self._status_var = tk.StringVar(value="Выберите файл или папку для сканирования.")
        tk.Label(status_bar, textvariable=self._status_var,
                 bg="#16213e", fg="#777", font=("Segoe UI", 9),
                 anchor="w").pack(side="left", padx=10)

        self._count_var = tk.StringVar(value="")
        tk.Label(status_bar, textvariable=self._count_var,
                 bg="#16213e", fg="#aaa", font=("Segoe UI", 9, "bold"),
                 anchor="e").pack(side="right", padx=10)

    # ── File picking ─────────────────────────────────────────────────────────

    def _pick_file(self):
        p = filedialog.askopenfilename(
            title="Выберите плагин (.cs)",
            filetypes=[("C# files", "*.cs"), ("All files", "*.*")]
        )
        if p:
            self._path_var.set(p)

    def _pick_dir(self):
        p = filedialog.askdirectory(title="Выберите папку с плагинами")
        if p:
            self._path_var.set(p)

    # ── Scanning ─────────────────────────────────────────────────────────────

    def _start_scan(self):
        path = self._path_var.get().strip()
        if not path:
            messagebox.showwarning("Нет пути", "Укажите файл или папку для сканирования.")
            return

        if self._scan_thread and self._scan_thread.is_alive():
            return

        self._scan_btn.configure(state="disabled", text="⏳ Сканирую…")
        self._tree.delete(*self._tree.get_children())
        self._findings.clear()
        self._clear_detail()
        self._progress_var.set("Сканирование…")

        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(path,), daemon=True
        )
        self._scan_thread.start()

    def _scan_worker(self, path: str):
        files: List[str] = []
        p = Path(path)
        if p.is_file():
            files = [str(p)]
        elif p.is_dir():
            files = [str(f) for f in p.rglob("*.cs")]
        else:
            self.after(0, lambda: self._progress_var.set("❌ Путь не найден."))
            self.after(0, lambda: self._scan_btn.configure(
                state="normal", text="🔍  СКАНИРОВАТЬ"))
            return

        all_findings: List[Tuple[str, Finding]] = []
        total = len(files)
        for i, fpath in enumerate(files, 1):
            self.after(0, lambda i=i, t=total, f=fpath:
                       self._progress_var.set(
                           f"Сканирую {i}/{t}: {Path(f).name}"))
            for finding in scan_file(fpath):
                all_findings.append((fpath, finding))

        # Sort by severity desc, then file, then line
        all_findings.sort(
            key=lambda x: (-severity_score(x[1].rule.severity),
                           x[0], x[1].line_no)
        )

        self._findings = all_findings
        self.after(0, self._populate_tree)

    def _populate_tree(self):
        self._tree.delete(*self._tree.get_children())
        shown = 0
        for filepath, finding in self._findings:
            sev = finding.rule.severity
            if not self._sev_vars[sev].get():
                continue
            icon = SEVERITY_ICON[sev]
            fname = Path(filepath).name
            self._tree.insert(
                "", "end",
                values=(icon, finding.rule.id, fname,
                        finding.line_no, finding.rule.title),
                tags=(sev,)
            )
            shown += 1

        total = len(self._findings)
        critical = sum(1 for _, f in self._findings if f.rule.severity == "CRITICAL")
        high     = sum(1 for _, f in self._findings if f.rule.severity == "HIGH")

        self._count_var.set(
            f"Показано: {shown}  |  Всего: {total}  "
            f"|  🔴 {critical} CRITICAL  |  🟠 {high} HIGH"
        )

        if total == 0:
            self._status_var.set("✅ Подозрительный код не обнаружен.")
            self._progress_var.set("✅ Сканирование завершено — проблем не найдено.")
        else:
            self._progress_var.set(
                f"⚠️  Сканирование завершено. Найдено {total} потенциальных проблем."
            )
            self._status_var.set(
                "Выберите строку для просмотра деталей."
            )

        self._scan_btn.configure(state="normal", text="🔍  СКАНИРОВАТЬ")

    def _apply_filter(self):
        self._populate_tree()

    # ── Detail view ──────────────────────────────────────────────────────────

    def _on_select(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        idx = self._tree.index(sel[0])
        shown_items = [
            (fp, f) for fp, f in self._findings
            if self._sev_vars[f.rule.severity].get()
        ]
        if idx >= len(shown_items):
            return
        filepath, finding = shown_items[idx]
        self._show_detail(filepath, finding)

    def _clear_detail(self):
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.configure(state="disabled")

    def _show_detail(self, filepath: str, finding: Finding):
        t = self._detail_text
        t.configure(state="normal")
        t.delete("1.0", "end")

        r   = finding.rule
        sev = r.severity

        # ── Заголовок с иконкой уровня ──────────────────────────────────────
        t.insert("end", f"{SEVERITY_ICON[sev]}  {r.title}\n", "heading")
        t.insert("end", "─" * 52 + "\n", "sep")
        t.insert("end", "\n")

        # ── Бейдж опасности ─────────────────────────────────────────────────
        t.insert("end", "  Уровень опасности:  ", "label")
        t.insert("end", f" {sev} \n", f"badge_{sev}")
        t.insert("end", "\n")

        # ── Где нашли ───────────────────────────────────────────────────────
        t.insert("end", "  📁 Где нашли\n", "section")
        for label, val in [
            ("  Файл:",      Path(filepath).name),
            ("  Строка:",    str(finding.line_no)),
            ("  Категория:", r.category),
            ("  Правило:",   r.id),
        ]:
            t.insert("end", f"  {label:<14}", "label")
            t.insert("end", f"{val}\n", "value")
        t.insert("end", "\n")

        # ── Что именно нашло ────────────────────────────────────────────────
        t.insert("end", "  🔎 Что именно нашло\n", "section")
        t.insert("end",
            "  Сканер обнаружил следующую строку кода в плагине:\n", "hint")
        t.insert("end", "\n")
        t.insert("end",
            f"  Строка {finding.line_no}:  {finding.line_text.strip()}\n", "code")
        t.insert("end", "\n")
        t.insert("end",
            f"  Сработало на:  {finding.match_text}\n", "match")
        t.insert("end", "\n")

        # ── Контекст кода ───────────────────────────────────────────────────
        context = self._get_context(filepath, finding.line_no, radius=5)
        if context:
            t.insert("end", "  📄 Контекст кода (строки вокруг):\n", "section")
            t.insert("end",
                "  Стрелка >>> указывает на строку где найдена проблема\n", "hint")
            t.insert("end", "\n")
            t.insert("end", context + "\n", "code")

        # ── Чем это опасно ──────────────────────────────────────────────────
        t.insert("end", "  ⚠️  Чем это опасно\n", "section")
        t.insert("end", f"  {r.description}\n", "desc")
        t.insert("end", "\n")

        # ── Что делать ──────────────────────────────────────────────────────
        t.insert("end", "  ✅ Что делать\n", "section")
        rec = self._get_recommendation(r)
        for line in rec.splitlines():
            t.insert("end", f"  {line}\n", "rec")
        t.insert("end", "\n")

        # ── Полный путь к файлу ─────────────────────────────────────────────
        t.insert("end", "  📂 Полный путь к файлу\n", "section")
        t.insert("end", f"  {filepath}\n", "path")

        t.configure(state="disabled")
        t.see("1.0")

    def _get_context(self, filepath: str, line_no: int, radius: int = 4) -> str:
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            start = max(0, line_no - 1 - radius)
            end   = min(len(lines), line_no + radius)
            result = []
            for i, ln in enumerate(lines[start:end], start=start + 1):
                marker = ">>>" if i == line_no else "   "
                result.append(f"  {marker} {i:4}: {ln.rstrip()}")
            return "\n".join(result) + "\n"
        except Exception:
            return ""

    def _get_recommendation(self, rule: Rule) -> str:
        recs = {
            "C001": (
                "🚨 НЕМЕДЛЕННО удалите этот плагин или закомментируйте строку.\n"
                "Команды ownerid/moderatorid выдают права администратора.\n"
                "Проверьте список администраторов сервера (cfg/users.cfg)."
            ),
            "C002": (
                "🚨 Плагин может выдать кому-то права администратора программно.\n"
                "Проверьте, чей SteamID передаётся в permission.AddUserGroup.\n"
                "Удалите плагин и проверьте файл oxide/config/permissions."
            ),
            "C003": (
                "🚨 КРИТИЧНО: Плагин запускает системные процессы.\n"
                "Это позволяет выполнить любую команду на сервере.\n"
                "Немедленно удалите плагин и проверьте сервер на backdoor-файлы."
            ),
            "C004": (
                "🚨 КРИТИЧНО: Плагин компилирует код в рантайме.\n"
                "Может загружать и выполнять код с сервера автора плагина.\n"
                "Удалите плагин немедленно."
            ),
            "C005": (
                "Плагин делает HTTP-запросы на внешние URL.\n"
                "Проверьте все URL в коде — они должны быть только из конфига.\n"
                "Особенно опасны запросы, передающие данные игроков или сервера."
            ),
            "H001": (
                "Плагин отправляет IP-адреса или SteamID на внешний сервер.\n"
                "Это может нарушать конфиденциальность ваших игроков.\n"
                "Убедитесь что URL принадлежит легитимному сервису."
            ),
            "H002": (
                "Плагин записывает/удаляет файлы на сервере.\n"
                "Убедитесь, что пути ограничены папками oxide/data/ и config/.\n"
                "Запись за пределами этих папок — потенциальный backdoor."
            ),
            "H003": (
                "В плагине есть Base64-декодирование строк.\n"
                "Расшифруйте строки самостоятельно:\n"
                "  python -c \"import base64; print(base64.b64decode('СТРОКА').decode())\"\n"
                "Если результат — код или команда, плагин потенциально вредоносен."
            ),
            "H004": (
                "Плагин использует Harmony для патча методов игры.\n"
                "Само по себе нормально (многие плагины это делают),\n"
                "но проверьте КАКИЕ методы патчатся и что делают Prefix/Postfix."
            ),
            "H005": (
                "В коде жёстко прописан SteamID64.\n"
                "Проверьте: это SteamID автора плагина?\n"
                "Найдите все места использования этого SteamID в коде."
            ),
            "M001": (
                "SQL-запрос уязвим к инъекциям через пользовательские данные.\n"
                "Замените конкатенацию на параметризованные запросы (@0, @1, ...)."
            ),
            "M003": (
                "Webhook URL прошит прямо в код — это подозрительно.\n"
                "Легитимные плагины всегда берут webhook из конфига.\n"
                "Чей это webhook? Данные с вашего сервера могут уходить к автору."
            ),
        }
        return recs.get(rule.id, (
            "Изучите контекст этого кода вручную.\n"
            "Если код вам непонятен — лучше не использовать плагин без проверки."
        ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()

