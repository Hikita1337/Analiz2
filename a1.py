import os
import json
from pathlib import Path
import subprocess

REPORT_DIR = Path("reports")
files = list(REPORT_DIR.glob("ultra_report_*.json"))
html_files = list(REPORT_DIR.glob("ultra_report_*.html"))

if not files and not html_files:
    print("Файлы отчёта не найдены.")
    exit()

json_path = files[0] if files else None
html_path = html_files[0] if html_files else None

base_name = json_path.stem if json_path else html_path.stem
OUT = REPORT_DIR / f"split_{base_name}"
OUT.mkdir(exist_ok=True)

def split_json(path):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    blocks = {}
    for key, value in data.items():
        blocks[key] = value

    for key, value in blocks.items():
        out = OUT / f"{key}.json"
        with out.open("w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)

if json_path:
    split_json(json_path)

if html_path:
    with html_path.open("r", encoding="utf-8") as f:
        html = f.read()

    size = 5_000_000
    parts = [html[i:i+size] for i in range(0, len(html), size)]

    for idx, part in enumerate(parts, 1):
        out = OUT / f"html_part_{idx}.html"
        with out.open("w", encoding="utf-8") as f:
            f.write(part)

subprocess.run(["git", "add", str(OUT)])
subprocess.run(["git", "commit", "-m", f"Split {base_name} into multiple files"])
subprocess.run(["git", "push"])

print("Готово. Разделено и запушено.")