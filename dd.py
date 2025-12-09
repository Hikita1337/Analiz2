import re
import json
import os
import subprocess
from datetime import datetime

INPUT = "bigdump.txt"

# === 1. Создание папки отчёта ===
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
REPORT_DIR = f"reports/clean_report_{timestamp}"
os.makedirs(REPORT_DIR, exist_ok=True)

print(f"[✓] Создана папка отчёта: {REPORT_DIR}")

data = open(INPUT, "r", errors="ignore").read()

# === 2. Регулярные выражения ===
url_regex = r"https?://[^\s\"'<>]+"
ws_regex = r"wss?://[^\s\"'<>]+"
token_regex = r"(?:token|auth|key|api_key|bearer|jwt)[^\"'&\s=]*=*[A-Za-z0-9\.\-_]+"
json_regex = r"\{(?:[^{}]|(?:\{[^{}]*\}))*\}"

# === 3. Извлечение данных ===
urls = set(re.findall(url_regex, data))
wss = set(re.findall(ws_regex, data))
tokens = set(re.findall(token_regex, data))
jsons = re.findall(json_regex, data)

domains = set()
for url in urls:
    domain = re.findall(r"https?://([^/]+)", url)
    if domain:
        domains.add(domain[0])

xhr_like = [u for u in urls if any(x in u.lower() for x in ["xhr", "fetch", "api", "ajax"])]

# === 4. Сохранение данных ===
def save(name, content):
    path = os.path.join(REPORT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(content, (list, set)):
            for item in content:
                f.write(str(item) + "\n")
        else:
            f.write(str(content))
    print(f"[✓] {name} сохранён ({len(content) if isinstance(content, (list,set)) else 'ok'})")

save("urls.txt", urls)
save("domains.txt", domains)
save("websockets.txt", wss)
save("xhr_like.txt", xhr_like)
save("tokens_found.txt", tokens)

with open(os.path.join(REPORT_DIR, "json_blobs.txt"), "w", encoding="utf-8") as f:
    for j in jsons:
        f.write(j + "\n\n")

print("\n[✓] Все файлы отчёта успешно сохранены.")

# === 5. Автозагрузка в Git ===

print("\n[•] Подготавливаю git push...")

def run(cmd):
    print(f"[CMD] {cmd}")
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# add
add_res = run(f"git add {REPORT_DIR}")
if add_res.stderr:
    print(add_res.stderr)

# commit
commit_res = run(f'git commit -m "Автоотчёт трафика {timestamp}"')
if "nothing to commit" in commit_res.stdout:
    print("[!] Нет изменений для коммита.")
else:
    print(commit_res.stdout)

# push
push_res = run("git push")
print(push_res.stdout if push_res.stdout else push_res.stderr)

print("\n[✓] Готово. Отчёт создан и запушен.")