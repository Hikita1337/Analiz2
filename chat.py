import re
import json
import os
import subprocess

INPUT_FILE = "bigdump.txt"
OUTPUT_JSON = "reports/full_deep_analysis.json"
OUTPUT_TXT  = "reports/full_deep_analysis.txt"

# --- Детекторы паттернов -----------------------------

re_api = re.compile(r"(GET|POST|PUT|DELETE)\s+https?://[^\s\"']+")
re_fetch = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']")
re_ws_send = re.compile(r"ws\.send\s*\(\s*(.+?)\s*\)")
re_ws_recv = re.compile(r"onmessage\s*=\s*function\s*\(.*?\)")
re_json_block = re.compile(r"\{[\s\S]{10,5000}?\}", re.MULTILINE)
re_function = re.compile(r"function\s+([A-Za-z0-9_]+)\s*\(")
re_arrow = re.compile(r"([A-Za-z0-9_]+)\s*=\s*\((.*?)\)\s*=>")
re_roles = re.compile(r"(admin|moderator|owner|staff|privilege)", re.IGNORECASE)
re_chat_keywords = re.compile(
    r"(message|chat|sticker|pin|unpin|delete|mute|ban|kick|join|leave|room|typing)",
    re.IGNORECASE
)

# --- Рутовый классификатор ---------------------------

def classify_block(text):
    t = text.lower()

    if re.search(r"(ban|mute|kick|delete|pin|unpin|admin|moderator|privilege)", t):
        return "Admin"
    if re.search(r"(message|chat|sticker|typing|room|send|receive)", t):
        return "Chat"
    if re.search(r"(profile|avatar|user|account)", t):
        return "User"
    if re.search(r"(system|internal|debug|log)", t):
        return "System"
    if re.search(r"(file|upload|download)", t):
        return "Files"
    return "Other"

# --- Универсальный сборщик --------------------------------------------------------

def extract_all(dump):
    items = []

    lines = dump.splitlines()

    for i, line in enumerate(lines):
        context = "\n".join(lines[max(i-5,0):min(i+6, len(lines))])

        # API
        m = re_api.search(line)
        if m:
            items.append({
                "type": "HTTP_API",
                "match": m.group(),
                "context": context,
                "classification": classify_block(context)
            })

        # fetch
        m = re_fetch.search(line)
        if m:
            items.append({
                "type": "FETCH",
                "url": m.group(1),
                "context": context,
                "classification": classify_block(context)
            })

        # WS send
        m = re_ws_send.search(line)
        if m:
            items.append({
                "type": "WS_SEND",
                "payload": m.group(1),
                "context": context,
                "classification": classify_block(context)
            })

        # WS receive handler
        if re_ws_recv.search(line):
            items.append({
                "type": "WS_RECEIVE_HANDLER",
                "context": context,
                "classification": classify_block(context)
            })

        # functions
        m = re_function.search(line)
        if m:
            items.append({
                "type": "FUNCTION",
                "name": m.group(1),
                "context": context,
                "classification": classify_block(context)
            })

        # arrow functions
        m = re_arrow.search(line)
        if m:
            items.append({
                "type": "ARROW_FUNCTION",
                "name": m.group(1),
                "context": context,
                "classification": classify_block(context)
            })

        # JSON blocks
        if "{" in line and "}" in line:
            for jb in re_json_block.findall(line):
                if len(jb) < 2000:
                    items.append({
                        "type": "JSON_BLOCK",
                        "json": jb,
                        "classification": classify_block(jb)
                    })

    return items


# --- MAIN -------------------------------------------------------------

print("Loading dump...")
with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
    dump = f.read()

print("Extracting structures...")
items = extract_all(dump)

os.makedirs("reports", exist_ok=True)

print("Writing JSON report...")
with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(items, f, ensure_ascii=False, indent=2)

print("Writing TXT summary...")
with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
    for it in items:
        f.write(f"[{it['type']} / {it['classification']}]\n")
        f.write(it["context"])
        f.write("\n" + "="*80 + "\n")

print("Committing to repo...")
subprocess.run(["git", "add", "."])
subprocess.run(["git", "commit", "-m", "Deep full analysis update"])
subprocess.run(["git", "push"])

print("DONE.")