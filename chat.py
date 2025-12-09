import re
import json
import os
import hashlib
import subprocess

INPUT_FILE = "bigdump.txt"
OUTPUT_JSON = "reports/full_deep_analysis.json"
OUTPUT_TXT  = "reports/full_deep_analysis.txt"
HASH_FILE   = "reports/seen_hashes.txt"
LOG_INTERVAL = 5000  # строки

os.makedirs("reports", exist_ok=True)

# --- Регулярки ---
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

# --- Инициализация ---
seen_hashes = set()
if os.path.exists(HASH_FILE):
    with open(HASH_FILE, "r") as hf:
        for line in hf:
            seen_hashes.add(line.strip())

fj = open(OUTPUT_JSON, "w", encoding="utf-8")
ft = open(OUTPUT_TXT, "w", encoding="utf-8")
fh = open(HASH_FILE, "a", encoding="utf-8")

fj.write("[\n")
first_entry = True

context_window = []  # 5 строк до/после для контекста
WINDOW_SIZE = 5

with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for idx, line in enumerate(f, 1):
        context_window.append(line.rstrip())
        if len(context_window) > 2*WINDOW_SIZE+1:
            context_window.pop(0)

        context = "\n".join(context_window)

        items = []

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
            for jb in re_json_block.findall(line):
                if len(jb)<2000: items.append({"type":"JSON_BLOCK","json":jb,"classification":classify_block(jb)})

        # --- проверка уникальности и запись ---
        for it in items:
            content_str = it.get("context", it.get("json","")).encode('utf-8')
            content_hash = hashlib.md5(content_str).hexdigest()
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)
            fh.write(content_hash+"\n")
            fh.flush()

            if not first_entry:
                fj.write(",\n")
            else:
                first_entry = False
            json.dump(it, fj, ensure_ascii=False)
            ft.write(f"[{it['type']} / {it['classification']}]\n")
            ft.write(content_str.decode('utf-8') + "\n" + "="*80 + "\n")

        if idx % LOG_INTERVAL == 0:
            print(f"Processed {idx} lines...")

fj.write("\n]\n")
fj.close()
ft.close()
fh.close()

# --- git push ---
subprocess.run(["git","add","."])
subprocess.run(["git","commit","-m","Deep full analysis update"])
subprocess.run(["git","push"])

print("DONE.")