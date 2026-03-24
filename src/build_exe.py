"""
Скрипт для сборки анализатора в .exe
Использует PyInstaller
"""

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    """Устанавливает необходимые пакеты"""
    print("📦 Установка зависимостей...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "PySide6", "pyinstaller"])

def build_exe():
    """Собирает .exe файл"""
    print("🔨 Сборка .exe файла...")
    repo_root = Path(__file__).resolve().parent.parent  # CHANGE: resolve repo root relative to this script
    scanner_path = repo_root / "src" / "gui_pyside6.py"  # CHANGE: build the new PySide6 desktop entrypoint instead of the legacy Flet UI
    icon_path = repo_root / "logo" / "logo.ico"  # CHANGE: resolve Windows icon path from repository layout
    
    # Параметры PyInstaller
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=RustPluginScanner",
        "--onefile",
        "--windowed",
        "--clean",
        "--noconfirm",
        "--hidden-import=PySide6",
        "--hidden-import=shiboken6",
        str(scanner_path)
    ]

    if icon_path.is_file():  # CHANGE: embed icon only when the expected file is present
        cmd.append(f"--icon={icon_path}")  # CHANGE: pass resolved .ico path to PyInstaller
        cmd.append(f"--add-data={icon_path}{os.pathsep}logo")  # CHANGE: bundle runtime icon asset for page.window.icon lookup
    
    subprocess.check_call(cmd)
    
    print("✅ Сборка завершена!")
    print(f"📁 Файл находится в: {Path('dist/RustPluginScanner.exe').absolute()}")

if __name__ == "__main__":
    try:
        install_requirements()
        build_exe()
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        sys.exit(1)
