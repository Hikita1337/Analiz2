import json, os, subprocess, sys
from pathlib import Path
from datetime import datetime

REPORT_DIR = Path("deep_reports_processed")
REPORT_DIR.mkdir(exist_ok=True)

FILES_TO_PROCESS = [
    "deep_reports/base64_2025-12-10_09-19-04.json",
    "deep_reports/hex_2025-12-10_09-19-05.json",
    "deep_reports/pf_predictive_analysis_2025-12-10_09-19-05.json",
    "deep_reports/ws_raw_unique_2025-12-10_09-19-06.json"
]

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, suffix):
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_path = REPORT_DIR / f"{suffix}_{ts}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return file_path

def git_lfs_push(file_path, msg="Авто-отчет"):
    try:
        subprocess.run(["git", "lfs", "track", str(file_path)], check=True)
        subprocess.run(["git", "add", str(file_path)], check=True)
        subprocess.run(["git", "commit", "-m", msg], check=True)
        subprocess.run(["git", "pull", "--rebase"], check=True)
        subprocess.run(["git", "push"], check=True)
        print(f"[*] Файл успешно запушен через Git LFS: {file_path}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Git ошибка: {e}")

def process_files():
    for file_path in FILES_TO_PROCESS:
        data = load_json(file_path)
        print(f"[INFO] Обработка {file_path} ({len(data)} элементов)")
        
        # Разделяем на уникальные элементы
        if isinstance(data, list):
            unique_items = list({json.dumps(item, sort_keys=True): item for item in data}.values())
            save_json(unique_items, Path(file_path).stem + "_unique")
        elif isinstance(data, dict):
            # Для pf_predictive_analysis
            result = {}
            for key, items in data.items():
                if isinstance(items, list):
                    result[key] = list({json.dumps(item, sort_keys=True): item for item in items}.values())
                else:
                    result[key] = items
            save_json(result, Path(file_path).stem + "_unique")
        else:
            print(f"[WARN] Неизвестный формат: {file_path}")

if __name__=="__main__":
    process_files()