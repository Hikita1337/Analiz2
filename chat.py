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
CHUNK_SIZE      = 100
LOG_EVERY       = 1

os.makedirs("reports", exist_ok=True)

# --- Регулярки ---
re_api = re.compile(r"(GET|POST|PUT|DELETE)\s+https?://[^\s\"']+")
re_fetch = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']")
re_ws_send = re.compile(r"ws\.send\s*\(\s*(.+?)\s*\)")
re_ws_recv = re.compile(r"onmessage\s*=\s*function\s*\(.*?\)")
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

seen_hashes = set()

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
    except Exception as e:
        with open(SKIP_FILE, "a", encoding="utf-8") as sf:
            sf.write(f"LINE ERROR: {line}\nException: {e}\n{'-'*50}\n")
    return items

# --- MAIN ---
line_count = 0
items_written = 0

with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f, \
     open(OUTPUT_JSON_ALL, "w", encoding="utf-8") as fj, \
     open(OUTPUT_TXT_ALL, "w", encoding="utf-8") as ft:

    fj.write("[\n")
    first_entry = True
    chunk_lines = []
    prev_lines = []

    for line in f:
        line_count += 1
        chunk_lines.append(line.rstrip())
        prev_lines.append(line.rstrip())
        if len(prev_lines) > 10: prev_lines.pop(0)

        if len(chunk_lines) >= CHUNK_SIZE:
            for i, l in enumerate(chunk_lines):
                context = "\n".join(chunk_lines[max(i-5,0):min(i+6,len(chunk_lines))])
                try:
                    for it in process_line(l, context):
                        content_hash = hashlib.md5(it.get("context", it.get("json","")).encode('utf-8')).hexdigest()
                        if content_hash in seen_hashes: continue
                        seen_hashes.add(content_hash)
                        if not first_entry: fj.write(",\n")
                        else: first_entry = False
                        json.dump(it, fj, ensure_ascii=False)
                        ft.write(f"[{it['type']} / {it['classification']}]\n")
                        ft.write(it.get("context", it.get("json","")) + "\n" + "="*80 + "\n")
                        items_written += 1
                except Exception as e:
                    with open(SKIP_FILE, "a", encoding="utf-8") as sf:
                        sf.write(f"SKIPPED LINE: {l}\nException: {e}\nContext:\n{context}\n{'-'*50}\n")
            chunk_lines = []

        if line_count % LOG_EVERY == 0:
            print(f"Processed {line_count} lines, written items: {items_written}")

    # --- остаток ---
    for i, l in enumerate(chunk_lines):
        context = "\n".join(chunk_lines[max(i-5,0):min(i+6,len(chunk_lines))])
        try:
            for it in process_line(l, context):
                content_hash = hashlib.md5(it.get("context", it.get("json","")).encode('utf-8')).hexdigest()
                if content_hash in seen_hashes: continue
                seen_hashes.add(content_hash)
                if not first_entry: fj.write(",\n")
                else: first_entry = False
                json.dump(it, fj, ensure_ascii=False)
                ft.write(f"[{it['type']} / {it['classification']}]\n")
                ft.write(it.get("context", it.get("json","")) + "\n" + "="*80 + "\n")
                items_written += 1
        except Exception as e:
            with open(SKIP_FILE, "a", encoding="utf-8") as sf:
                sf.write(f"SKIPPED LINE: {l}\nException: {e}\nContext:\n{context}\n{'-'*50}\n")

    fj.write("\n]\n")

print(f"Completed processing {line_count} lines, total items: {items_written}")
print(f"Skipped lines saved in {SKIP_FILE}")

# --- Chat/Admin фильтрация ---
with open(OUTPUT_JSON_ALL,"r",encoding="utf-8") as fj:
    all_items = json.load(fj)
chat_admin = [x for x in all_items if x["classification"] in ["Chat","Admin"]]

with open(OUTPUT_JSON_CMD,"w",encoding="utf-8") as fj:
    json.dump(chat_admin,fj,ensure_ascii=False,indent=2)

with open(OUTPUT_TXT_CMD,"w",encoding="utf-8") as ft:
    for it in chat_admin:
        ft.write(f"[{it['type']} / {it['classification']}]\n")
        ft.write(it.get("context", it.get("json","")) + "\n" + "="*80 + "\n")

# --- git push ---
subprocess.run(["git","add","."])
subprocess.run(["git","commit","-m","Safe analysis with skipped lines handling"])
subprocess.run(["git","push"])

print("DONE: Analysis complete, Chat/Admin extracted.")