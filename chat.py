import re
import json
import os
import subprocess
import hashlib
from tqdm import tqdm

# --- Параметры ---
INPUT_FILE = "bigdump.txt"
OUTPUT_JSON = "reports/full_deep_analysis.json"
OUTPUT_TXT  = "reports/full_deep_analysis.txt"
CHUNK_SIZE = 10000  # количество строк за один пакет

# --- Регулярки и классификатор ---
re_api = re.compile(r"(GET|POST|PUT|DELETE)\s+https?://[^\s\"']+")
re_fetch = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']")
re_ws_send = re.compile(r"ws\.send\s*\(\s*(.+?)\s*\)")
re_ws_recv = re.compile(r"onmessage\s*=\s*function\s*\(.*?\)")
re_json_block = re.compile(r"\{[\s\S]{10,5000}?\}", re.MULTILINE)
re_function = re.compile(r"function\s+([A-Za-z0-9_]+)\s*\(")
re_arrow = re.compile(r"([A-Za-z0-9_]+)\s*=\s*\((.*?)\)\s*=>")

keywords_admin = r"(ban|mute|kick|delete|pin|unpin|admin|moderator|privilege)"
keywords_chat  = r"(message|chat|sticker|typing|room|send|receive)"
keywords_user  = r"(profile|avatar|user|account)"
keywords_system= r"(system|internal|debug|log)"
keywords_files = r"(file|upload|download)"

def classify_block(text):
    t = text.lower()
    if re.search(keywords_admin, t): return "Admin"
    if re.search(keywords_chat, t): return "Chat"
    if re.search(keywords_user, t): return "User"
    if re.search(keywords_system, t): return "System"
    if re.search(keywords_files, t): return "Files"
    return "Other"

# --- Создание папки reports ---
os.makedirs("reports", exist_ok=True)

# --- Множество для уникальных блоков ---
seen_hashes = set()

# --- Определяем общее количество строк для прогресс-бара ---
with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    total_lines = sum(1 for _ in f)

# --- Начало JSON ---
with open(OUTPUT_JSON, "w", encoding="utf-8") as fj, open(OUTPUT_TXT, "w", encoding="utf-8") as ft:
    fj.write("[\n")
    first_entry = True
    chunk_lines = []

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f, tqdm(total=total_lines, desc="Processing lines") as pbar:
        for line_number, line in enumerate(f, start=1):
            chunk_lines.append(line.rstrip())

            if len(chunk_lines) >= CHUNK_SIZE:
                for i, l in enumerate(chunk_lines):
                    context = "\n".join(chunk_lines[max(i-5,0):min(i+6,len(chunk_lines))])
                    items = []

                    m = re_api.search(l)
                    if m: items.append({"type":"HTTP_API","match":m.group(),"context":context,"classification":classify_block(context)})
                    m = re_fetch.search(l)
                    if m: items.append({"type":"FETCH","url":m.group(1),"context":context,"classification":classify_block(context)})
                    m = re_ws_send.search(l)
                    if m: items.append({"type":"WS_SEND","payload":m.group(1),"context":context,"classification":classify_block(context)})
                    if re_ws_recv.search(l):
                        items.append({"type":"WS_RECEIVE_HANDLER","context":context,"classification":classify_block(context)})
                    m = re_function.search(l)
                    if m: items.append({"type":"FUNCTION","name":m.group(1),"context":context,"classification":classify_block(context)})
                    m = re_arrow.search(l)
                    if m: items.append({"type":"ARROW_FUNCTION","name":m.group(1),"context":context,"classification":classify_block(context)})
                    if "{" in l and "}" in l:
                        for jb in re_json_block.findall(l):
                            if len(jb)<2000: items.append({"type":"JSON_BLOCK","json":jb,"classification":classify_block(jb)})

                    # --- проверка на уникальность ---
                    for it in items:
                        content_str = it.get("context", it.get("json","")).encode('utf-8')
                        content_hash = hashlib.md5(content_str).hexdigest()
                        if content_hash in seen_hashes:
                            continue
                        seen_hashes.add(content_hash)

                        if not first_entry:
                            fj.write(",\n")
                        else:
                            first_entry = False
                        json.dump(it, fj, ensure_ascii=False)
                        ft.write(f"[{it['type']} / {it['classification']}]\n")
                        ft.write(content_str.decode('utf-8') + "\n" + "="*80 + "\n")

                chunk_lines = []

            pbar.update(1)

        # --- обработка оставшихся строк ---
        for i, l in enumerate(chunk_lines):
            context = "\n".join(chunk_lines[max(i-5,0):min(i+6,len(chunk_lines))])
            items = []

            m = re_api.search(l)
            if m: items.append({"type":"HTTP_API","match":m.group(),"context":context,"classification":classify_block(context)})
            m = re_fetch.search(l)
            if m: items.append({"type":"FETCH","url":m.group(1),"context":context,"classification":classify_block(context)})
            m = re_ws_send.search(l)
            if m: items.append({"type":"WS_SEND","payload":m.group(1),"context":context,"classification":classify_block(context)})
            if re_ws_recv.search(l):
                items.append({"type":"WS_RECEIVE_HANDLER","context":context,"classification":classify_block(context)})
            m = re_function.search(l)
            if m: items.append({"type":"FUNCTION","name":m.group(1),"context":context,"classification":classify_block(context)})
            m = re_arrow.search(l)
            if m: items.append({"type":"ARROW_FUNCTION","name":m.group(1),"context":context,"classification":classify_block(context)})
            if "{" in l and "}" in l:
                for jb in re_json_block.findall(l):
                    if len(jb)<2000: items.append({"type":"JSON_BLOCK","json":jb,"classification":classify_block(jb)})

            for it in items:
                content_str = it.get("context", it.get("json","")).encode('utf-8')
                content_hash = hashlib.md5(content_str).hexdigest()
                if content_hash in seen_hashes:
                    continue
                seen_hashes.add(content_hash)

                if not first_entry:
                    fj.write(",\n")
                else:
                    first_entry = False
                json.dump(it, fj, ensure_ascii=False)
                ft.write(f"[{it['type']} / {it['classification']}]\n")
                ft.write(content_str.decode('utf-8') + "\n" + "="*80 + "\n")

    fj.write("\n]\n")

# --- git push ---
subprocess.run(["git","add","."])
subprocess.run(["git","commit","-m","Deep full analysis update"])
subprocess.run(["git","push"])

print("DONE.")