import re
import json
import os
import hashlib
import subprocess

INPUT_FILE = "bigdump.txt"
OUTPUT_JSON_ALL = "reports/full_safe_analysis.json"
OUTPUT_TXT_ALL  = "reports/full_safe_analysis.txt"
OUTPUT_JSON_CMD = "reports/chat_admin_commands.json"
OUTPUT_TXT_CMD  = "reports/chat_admin_commands.txt"
SKIP_FILE       = "reports/skipped_lines.txt"
CHUNK_SIZE      = 1000  # количество строк за один пакет

os.makedirs("reports", exist_ok=True)

# --- Регулярки ---
re_api = re.compile(r"(GET|POST|PUT|DELETE)\s+https?://[^\s\"']+")
re_fetch = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']")
re_ws_send = re.compile(r"ws\.send\s*\(\s*(.+?)\s*\)")
re_ws_recv = re.compile(r"onmessage\s*=\s*function\s*\(.*?\)")
re_function = re.compile(r"function\s+([A-Za-z0-9_]+)\s*\(")
re_arrow = re.compile(r"([A-Za-z0-9_]+)\s*=\s*\((.*?)\)\s*=>")

# --- Классификатор ---
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

# --- Для уникальности ---
seen_hashes = set()

# --- Функция обработки строки ---
def process_line(line, context):
    items = []
    try:
        m = re_api.search(line)
        if m: items.append({"type":"HTTP_API","match":m.group(),"context":context,"classification":classify_block(context)})
        m = re_fetch.search(line)
        if m: items.append({"type":"FETCH","url":m.group(1),"context":context,"classification":classify_block(context)})
        m = re_ws_send.search(line)
        if m: items.append({"type":"WS_SEND","payload":m.group(1),"context":context,"classification":classify_block(context)})
        if re_ws_recv.search(line):
            items.append({"type":"WS_RECEIVE_HANDLER","context":context,"classification":classify_block(context)})
        m = re_function.search(line)
        if m: items.append({"type":"FUNCTION","name":m.group(1),"context":context,"classification":classify_block(context)})
        m = re_arrow.search(line)
        if m: items.append({"type":"ARROW_FUNCTION","name":m.group(1),"context":context,"classification":classify_block(context)})
        if "{" in line and "}" in line:
            items.append({"type":"JSON_BLOCK","json":line,"classification":classify_block(line)})
    except Exception as e:
        with open(SKIP_FILE, "a", encoding="utf-8") as sf:
            sf.write(f"{line}\nERROR: {e}\n{'-'*50}\n")
    return items

# --- MAIN PROCESSING ---
with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    chunk_lines = []
    all_items = []
    for idx, line in enumerate(f, 1):
        chunk_lines.append(line.rstrip())
        if len(chunk_lines) >= CHUNK_SIZE:
            for i, l in enumerate(chunk_lines):
                context = "\n".join(chunk_lines[max(i-5,0):min(i+6,len(chunk_lines))])
                for it in process_line(l, context):
                    content_hash = hashlib.md5(it.get("context", it.get("json","")).encode('utf-8')).hexdigest()
                    if content_hash not in seen_hashes:
                        seen_hashes.add(content_hash)
                        all_items.append(it)
            chunk_lines = []
    # --- Обработка остатка ---
    for i, l in enumerate(chunk_lines):
        context = "\n".join(chunk_lines[max(i-5,0):min(i+6,len(chunk_lines))])
        for it in process_line(l, context):
            content_hash = hashlib.md5(it.get("context", it.get("json","")).encode('utf-8')).hexdigest()
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                all_items.append(it)

# --- Сохраняем полный JSON и текст ---
with open(OUTPUT_JSON_ALL,"w",encoding="utf-8") as fj:
    json.dump(all_items,fj,ensure_ascii=False,indent=2)

with open(OUTPUT_TXT_ALL,"w",encoding="utf-8") as ft:
    for it in all_items:
        ft.write(f"[{it['type']} / {it['classification']}]\n")
        ft.write(it.get("context", it.get("json","")) + "\n" + "="*80 + "\n")

# --- Фильтрация Chat/Admin ---
chat_admin = [x for x in all_items if x["classification"] in ["Chat","Admin"]]

with open(OUTPUT_JSON_CMD,"w",encoding="utf-8") as fj:
    json.dump(chat_admin,fj,ensure_ascii=False,indent=2)

with open(OUTPUT_TXT_CMD,"w",encoding="utf-8") as ft:
    for it in chat_admin:
        ft.write(f"[{it['type']} / {it['classification']}]\n")
        ft.write(it.get("context", it.get("json","")) + "\n" + "="*80 + "\n")

# --- git push ---
subprocess.run(["git","add","."])
subprocess.run(["git","commit","-m","Full chat/admin analysis update"])
subprocess.run(["git","push"])

print("DONE: Full analysis + Chat/Admin extraction complete.")
print(f"Total items: {len(all_items)}, Chat/Admin items: {len(chat_admin)}")
print(f"Skipped lines logged in {SKIP_FILE}")