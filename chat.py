import os
import re
import json
import hashlib
from tqdm import tqdm

# --- Настройки ---
INPUT_DIRS = ["final_part1", "final_part2", "final_part3"]
OUTPUT_JSON = "reports/api_ws_analysis.json"
OUTPUT_TXT = "reports/api_ws_analysis.txt"

# --- Регулярки ---
re_api = re.compile(r"(GET|POST|PUT|DELETE)\s+https?://[^\s\"']+")
re_ws_send = re.compile(r"ws\.send\s*\(\s*(.+?)\s*\)")
re_ws_recv = re.compile(r"onmessage\s*=\s*function\s*\(.*?\)")

# --- Создание папки для отчётов ---
os.makedirs("reports", exist_ok=True)

# --- Множество для уникальных записей ---
seen_hashes = set()

# --- Функция обработки файла ---
def process_file(file_path):
    items = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                context = "\n".join(lines[max(i-5,0):min(i+6,len(lines))])
                
                # HTTP API
                for m in re_api.findall(line):
                    h = hashlib.md5((m+context).encode()).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        items.append({"type":"HTTP_API","match":m,"context":context})
                
                # WS send
                for m in re_ws_send.findall(line):
                    h = hashlib.md5((m+context).encode()).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        items.append({"type":"WS_SEND","payload":m,"context":context})
                
                # WS receive
                if re_ws_recv.search(line):
                    h = hashlib.md5(("WS_RECEIVE"+context).encode()).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        items.append({"type":"WS_RECEIVE_HANDLER","context":context})
    except Exception as e:
        print(f"Ошибка при обработке {file_path}: {e}")
    return items

# --- Основной цикл по папкам ---
all_items = []
for folder in INPUT_DIRS:
    print(f"Обрабатываем папку {folder}...")
    files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(folder) for f in filenames
             if not f.lower().endswith(('.png', '.webp', '.bin'))]
    for file in tqdm(files, desc=f"Файлы в {folder}"):
        all_items.extend(process_file(file))

# --- Сохраняем JSON ---
with open(OUTPUT_JSON, "w", encoding="utf-8") as fjson:
    json.dump(all_items, fjson, ensure_ascii=False, indent=2)

# --- Сохраняем TXT ---
with open(OUTPUT_TXT, "w", encoding="utf-8") as ftxt:
    for it in all_items:
        ftxt.write(f"[{it['type']}]\n")
        ftxt.write(it.get("match", it.get("payload","")) + "\n")
        ftxt.write(it["context"] + "\n" + "="*80 + "\n")

print(f"Готово! Найдено {len(all_items)} уникальных записей.")