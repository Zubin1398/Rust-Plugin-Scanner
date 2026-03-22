"""
Builds the desktop application into a standalone Windows executable.
"""

import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
SOURCE_FILE = ROOT_DIR / "src" / "scanner_flet.py"
BUILD_DIR = ROOT_DIR / "build"
DIST_DIR = ROOT_DIR / "dist"
OUTPUT_EXE = DIST_DIR / "RustPluginScanner.exe"
ICON_FILE = ROOT_DIR / "logo" / "logo.ico"


def install_requirements() -> None:
    """Installs project dependencies from requirements.txt."""
    print("Installing project dependencies...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
        cwd=ROOT_DIR,
    )


def build_exe() -> None:
    """Builds the executable with PyInstaller."""
    print("Building RustPluginScanner.exe...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name=RustPluginScanner",
        "--onefile",
        "--windowed",
        "--clean",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        f"--specpath={BUILD_DIR}",
    ]
    if ICON_FILE.exists():
        cmd.append(f"--icon={ICON_FILE}")
    cmd.append(str(SOURCE_FILE))
    subprocess.check_call(cmd, cwd=ROOT_DIR)
    print(f"Build completed: {OUTPUT_EXE}")


if __name__ == "__main__":
    try:
        install_requirements()
        build_exe()
    except Exception as exc:
        print(f"Build failed: {exc}")
        sys.exit(1)
