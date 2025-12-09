from pathlib import Path

# Папка с отчётами
REPORT_DIR = Path("reports")
README_FILE = Path("reports") / "README.md"

# Список отчётов ultra_report_*
report_files = sorted(REPORT_DIR.glob("ultra_report_*"))

# Сбор ссылок на GitHub
repo_url = "https://github.com/Hikita1337/Analiz2/blob/main/reports/"

lines = ["# Отчёты Ultra Analyzer\n"]
for f in report_files:
    link = repo_url + f.name
    lines.append(f"- [{f.name}]({link})")

README_FILE.write_text("\n".join(lines), encoding="utf-8")
print(f"[*] README.md создан: {README_FILE}")
