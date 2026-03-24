# Rust Plugin Security Scanner _**v2.1.0**_

Современный desktop-анализатор безопасности для Rust Oxide/uMod plugins.

## Что это

Приложение выполняет статический анализ `.cs` плагинов и помогает быстро находить:
- privilege escalation,
- remote code execution,
- suspicious network/data exfiltration patterns,
- reflection/obfuscation techniques,
- hardcoded credentials и unsafe code fragments.

## Текущий стек

- `PySide6` — desktop UI
- `PyInstaller` — сборка `.exe`
- `Python` — scanner core, CLI и exporters

## Быстрый запуск

### Из исходников

```bash
pip install -r requirements.txt
python src\gui_pyside6.py
```

### CLI

```bash
python src\cli.py "path\to\plugin.cs"
python src\cli.py "path\to\folder" --format json --output report.json
```

### Сборка `.exe`

```bash
python src\build_exe.py
```

Готовый файл:

```bash
dist\RustPluginScanner.exe
```

## Архитектура

```text
src/
├── gui_pyside6.py     # основной desktop UI
├── cli.py             # command-line entrypoint
├── build_exe.py       # сборка Windows .exe
└── core/
    ├── models.py      # Rule / Finding
    ├── rules.py       # rule registry + app metadata
    ├── scanner.py     # scan_file / scan_target / get_context
    └── exporters.py   # TXT / JSON / HTML export
```

