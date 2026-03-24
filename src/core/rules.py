from typing import List

from .models import Rule

APP_NAME = "Rust Plugin Security Scanner"
APP_VERSION = "2.1.0"
APP_AUTHOR = "MMZ4"

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


# CHANGE: extracted scanner rules from the legacy monolithic Flet file into a reusable core module
RULES: List[Rule] = [
    Rule("C001", "CRITICAL", "Admin Escalation", "Выдача прав администратора через ConsoleSystem", "Плагин выполняет команду ownerid/moderatorid через ConsoleSystem.Run", [r'ConsoleSystem\.Run\s*\([^)]*"ownerid', r'ConsoleSystem\.Run\s*\([^)]*"moderatorid', r'"ownerid\s+\d{17}', r'"moderatorid\s+\d{17}'], ["//", "example", "sample"]),
    Rule("C002", "CRITICAL", "Admin Escalation", "Прямое добавление в группу oxide.admin", "Плагин программно добавляет игроков в группу oxide.admin", [r'permission\.AddUserGroup\s*\([^)]*"oxide\.admin"', r'ServerUsers\.Set\s*\([^,]+,\s*ServerUsers\.UserGroup\.Owner'], ["//", "hasPermission"]),
    Rule("C003", "CRITICAL", "Remote Code Execution", "Запуск системных процессов / shell-команд", "Плагин создаёт системный процесс (cmd.exe, powershell, bash)", [r'System\.Diagnostics\.Process', r'ProcessStartInfo', r'Process\.Start\s*\(', r'"cmd\.exe"', r'"powershell"', r'"/bin/bash"'], ["//"]),
    Rule("C004", "CRITICAL", "Remote Code Execution", "Динамическая компиляция и выполнение кода", "Плагин компилирует и выполняет код в рантайме", [r'Assembly\.Load\s*\(', r'Assembly\.LoadFrom\s*\(', r'Activator\.CreateInstance.*Assembly'], ["//", "Activator.CreateInstance<T>()"]),
    Rule("C005", "CRITICAL", "Data Exfiltration", "Отправка данных на жёстко прописанный URL", "Плагин отправляет HTTP-запросы на неизвестный URL", [r'WebClient\s*\(', r'HttpClient\s*\(', r'webrequest\.Enqueue\s*\(["\']https?://(?!api\.steampowered|discord\.com|umod\.org)'], ["//", "api.steampowered", "discord"]),
    Rule("C006", "CRITICAL", "Reflection", "Вызов ConsoleSystem через рефлексию", "Плагин вызывает ConsoleSystem.Run через рефлексию для скрытия", [r'Type\.GetType\s*\(\s*"ConsoleSystem', r'GetMethod\s*\(\s*"Run"'], ["//"]),
    Rule("C007", "CRITICAL", "Reflection", "Динамический вызов Process.Start через рефлексию", "Плагин запускает процессы через рефлексию", [r'Type\.GetType\s*\(\s*"System\.Diagnostics\.Process'], ["//"]),
    Rule("H001", "HIGH", "Data Exfiltration", "Отправка SteamID / IP-адресов на внешний сервер", "Плагин собирает SteamID или IP-адреса игроков и отправляет их", [r'player\.UserIDString.*webrequest', r'player\.net\.connection\.ipaddress.*webrequest', r'ip-api\.com', r'ipinfo\.io'], ["//", "discord", "ban"]),
    Rule("H002", "HIGH", "File System", "Запись/удаление произвольных файлов на сервере", "Плагин пишет или удаляет файлы за пределами стандартных директорий", [r'File\.Delete\s*\(', r'File\.WriteAllText\s*\(', r'File\.WriteAllBytes\s*\(', r'Directory\.Delete\s*\('], ["//", "oxide/data", "config/"]),
    Rule("H003", "HIGH", "Obfuscation", "Base64-декодирование строк в рантайме", "Плагин декодирует строки из Base64 во время выполнения", [r'Convert\.FromBase64String\s*\('], ["//", "ImageLibrary"]),
    Rule("H004", "HIGH", "Harmony Patch", "Потенциально опасный Harmony-патч", "Плагин использует Harmony для патча игровых методов", [r'\[HarmonyPatch\(', r'harmony\.Patch\s*\('], ["//"]),
    Rule("H005", "HIGH", "Credentials", "Жёстко прописанные SteamID", "В коде найдены жёстко прописанные SteamID64", [r'(?<!\w)7656119\d{10}(?!\d)'], ["//", "example", "test", "0"]),
    Rule("H006", "HIGH", "Obfuscation", "XOR-шифрование строк в рантайме", "Плагин использует XOR для шифрования строк", [r'\[\w+\]\s*\^=', r'data\[i\]\s*\^='], ["//", "checksum"]),
    Rule("H007", "HIGH", "Obfuscation", "Динамическая сборка строк из частей", "Строки собираются из частей в рантайме", [r'string\.Concat\s*\(', r'string\.Join\s*\(\s*""'], ["//", "config"]),
    Rule("H008", "HIGH", "Obfuscation", "Многослойное шифрование данных", "Данные проходят через несколько слоёв шифрования", [r'Convert\.FromBase64String.*\^=', r'Array\.Reverse.*Convert\.FromBase64'], ["//"]),
    Rule("H009", "HIGH", "Reflection", "Создание делегатов через рефлексию", "Плагин создаёт делегаты динамически", [r'Delegate\.CreateDelegate\s*\('], ["//"]),
    Rule("H010", "HIGH", "Reflection", "Использование Expression Trees", "Плагин использует LINQ Expressions для генерации кода", [r'Expression\.Parameter\s*\(', r'Expression\.Call\s*\(', r'\.Compile\s*\(\s*\)'], ["//"]),
    Rule("M001", "MEDIUM", "SQL Injection", "SQL-запрос с интерполяцией строк", "SQL-запрос формируется через конкатенацию без параметризации", [r'Sql\.Builder\.Append\s*\(\s*\$"[^"]*\{', r'"SELECT.*WHERE.*\+\s*\w'], ["//", "@0"]),
    Rule("M002", "MEDIUM", "Reflection", "Использование рефлексии для вызова методов", "Плагин использует рефлексию для динамического вызова методов", [r'Type\.GetMethod\s*\(', r'MethodInfo\.Invoke\s*\('], ["//"]),
    Rule("M003", "MEDIUM", "Network", "Отправка данных через Discord Webhook", "Плагин отправляет данные на Discord webhook", [r'"https://discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"'], ["//", "config."]),
    Rule("M004", "MEDIUM", "Data Exfiltration", "Hardcoded API-ключ в коде", "В коде найден жёстко прописанный API-ключ или токен", [r'apiKey\s*=\s*"[A-Za-z0-9]{20,}"', r'token\s*=\s*"[A-Za-z0-9]{30,}"'], ["//", "config."]),
    Rule("M005", "MEDIUM", "Obfuscation", "Шифрование с жёстко прописанным ключом", "Плагин использует симметричное шифрование с ключом в коде", [r'Aes\.Create\s*\(', r'aes\.Key\s*=\s*Convert\.FromBase64String'], ["//"]),
    Rule("M006", "MEDIUM", "Obfuscation", "Использование char[] вместо строк", "Строки создаются из массивов char", [r'char\[\]\s+\w+\s*=\s*\{\s*\'[^\']\'\s*,'], ["//"]),
    Rule("M007", "MEDIUM", "Anti-Analysis", "Проверка на отладчик и песочницу", "Плагин проверяет окружение на признаки анализа", [r'Debugger\.IsAttached', r'\.Contains\s*\(\s*"sandbox"'], ["//"]),
    Rule("M008", "MEDIUM", "Anti-Analysis", "Time Bomb - отложенное выполнение", "Плагин активирует функциональность после определённой даты", [r'DateTime\.Now\s*[<>]', r'new\s+DateTime\s*\(\s*\d{4}'], ["//", "config"]),
    Rule("M009", "MEDIUM", "Steganography", "Чтение собственного исходного кода", "Плагин читает свой собственный .cs файл", [r'File\.ReadAllText\s*\([^)]*\.cs'], ["//", "config"]),
    Rule("M010", "MEDIUM", "Suspicious", "Математическое вычисление SteamID", "SteamID вычисляется через математические операции", [r'7656119\d+UL\s*[+\-*/]'], ["//"]),
    Rule("M011", "MEDIUM", "Suspicious", "Полиморфное выполнение", "Плагин случайно выбирает один из методов выполнения", [r'Environment\.TickCount\s*%'], ["//"]),
    Rule("M012", "MEDIUM", "Suspicious", "Создание файла автозагрузки плагина", "Плагин модифицирует autoload.txt", [r'autoload\.txt'], ["//"]),
    Rule("L001", "LOW", "Network", "HTTP-запросы к внешним сервисам", "Плагин делает HTTP-запросы", [r'webrequest\.Enqueue\s*\('], ["//"]),
    Rule("L002", "LOW", "Suspicious", "Запрос/изменение ConVar", "Плагин читает или изменяет серверные переменные", [r'ConVar\.\w+\.', r'ConsoleSystem\.Run\s*\('], ["//"]),
    Rule("L003", "LOW", "Suspicious", "Доступ к PlayerToken / auth-данным", "Плагин обращается к токенам аутентификации игроков", [r'player\.net\.connection\.token', r'connection\.token'], ["//"]),
    Rule("L004", "LOW", "Steganography", "Использование невидимых Unicode символов", "В коде обнаружены zero-width Unicode символы", [r'[\u200B-\u200F]'], ["//"]),
    Rule("L005", "LOW", "Suspicious", "Использование StackTrace", "Плагин анализирует стек вызовов", [r'new\s+StackTrace\s*\('], ["//", "error"]),
    Rule("L006", "LOW", "Suspicious", "Вредоносная логика в обработчике исключений", "Подозрительный код в catch-блоке", [r'catch\s*\([^)]*\)\s*\{[^}]*(ConsoleSystem|Process\.Start)'], ["//", "log"]),
    Rule("I001", "INFO", "Info", "Использование Timer/InvokeRepeating", "Плагин использует повторяющиеся таймеры", [r'timer\.Repeat\s*\(', r'InvokeRepeating\s*\('], ["//"]),
]
