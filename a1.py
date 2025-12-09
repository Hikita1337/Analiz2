import os
from pathlib import Path
from datetime import datetime
import subprocess
import sys

REPO_URL = "https://github.com/Hikita1337/Analiz2"
REPORT_DIR = Path("reports")
OUTPUT_RTF = REPORT_DIR / "ultra_reports_index.rtf"

def ensure_pypandoc():
    try:
        import pypandoc
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pypandoc"])

def list_reports():
    REPORT_DIR.mkdir(exist_ok=True)
    return sorted([f for f in REPORT_DIR.iterdir() if f.name.startswith("ultra_report_")])

def generate_rtf(reports):
    lines = ["# Отчёты Ultra Analyzer\n"]
    for f in reports:
        github_link = f"{REPO_URL}/blob/main/{f.as_posix()}"
        lines.append(f"- [{f.name}]({github_link})")

    md_text = "\n".join(lines)

    import pypandoc
    pypandoc.convert_text(
        md_text,
        to="rtf",
        format="md",
        outputfile=str(OUTPUT_RTF),
        extra_args=["--standalone"]
    )

def git_push():
    try:
        subprocess.run(["git", "add", str(OUTPUT_RTF)], check=True)
        subprocess.run(["git", "commit", "-m", "Индекс отчётов"], check=True)
        subprocess.run(["git", "pull", "--rebase"], check=True)
        subprocess.run(["git", "push"], check=True)
        print("[*] Индекс успешно запушен.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Git: {e}")

if __name__ == "__main__":
    ensure_pypandoc()
    reports = list_reports()
    if not reports:
        print("[!] Нет файлов ultra_report_*")
        sys.exit(0)

    generate_rtf(reports)
    git_push()

    print(f"[*] Создан файл: {OUTPUT_RTF}")
    print("[*] Готово.")
