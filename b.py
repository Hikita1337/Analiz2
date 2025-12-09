import re
import json
import os
import subprocess
from datetime import datetime
from collections import defaultdict

BUNDLE = "2025-12-09_09-42-51-297323.js"
TRAFFIC = "bigdump.txt"

REPORT_DIR = "deep_reports"

OUT_MAP = f"{REPORT_DIR}/runtime_map.json"
OUT_HIDDEN = f"{REPORT_DIR}/hidden_functions.json"
OUT_RNG = f"{REPORT_DIR}/rng_analysis.json"
OUT_CRASH = f"{REPORT_DIR}/crash_timing.json"
OUT_VULN = f"{REPORT_DIR}/security_findings.json"


# ======================================================
# 0. Создание папки для отчётов
# ======================================================
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)
    print(f"[+] Создана папка: {REPORT_DIR}")


# ======================================================
# 1. Извлечение всех функций из bundle
# ======================================================
FUNC_RE = re.compile(r"([a-zA-Z0-9_$]{2,})\s*=\s*function|\bfunction\s+([a-zA-Z0-9_$]{2,})\s*\(")

print("[*] Чтение bundle…")
with open(BUNDLE, "r", encoding="utf8", errors="ignore") as f:
    bundle = f.read()

bundle_funcs = set()

for match in FUNC_RE.finditer(bundle):
    name = match.group(1) or match.group(2)
    if name:
        bundle_funcs.add(name)

print(f"[+] Найдено {len(bundle_funcs)} функций в bundle")


# ======================================================
# 2. Извлечение runtime-событий из трафика
# ======================================================
METHOD_RE = re.compile(r'"method"\s*:\s*"([a-zA-Z0-9_]+)"')
DATA_RE = re.compile(r'"(crash|hash|salt|seed|delta|result|nonce)"\s*:\s*"([^"]+)"')

runtime_methods = set()
rng_events = []
crash_events = []

print("[*] Чтение traffic dump…")

with open(TRAFFIC, "r", encoding="utf8", errors="ignore") as f:
    for line in f:

        # RPC методы
        for m in METHOD_RE.findall(line):
            runtime_methods.add(m)

        # RNG data
        rng_match = DATA_RE.findall(line)
        if rng_match:
            for k, v in rng_match:
                rng_events.append({k: v})

        # crash timing
        if '"crash"' in line or '"finishRound"' in line:
            crash_events.append(line.strip())

print(f"[+] Найдено {len(runtime_methods)} runtime методов")
print(f"[+] Найдено {len(rng_events)} RNG событий")
print(f"[+] Найдено {len(crash_events)} crash-событий")


# ======================================================
# 3. Сопоставление runtime методов → мини-функций
# ======================================================
result_map = {}

for method in runtime_methods:
    pattern = re.compile(rf"[;,\{{]\s*([a-zA-Z0-9_$]{{2,}})\s*[:=][^=]*['\"]{method}['\"]")
    candidates = set()

    for match in pattern.finditer(bundle):
        candidates.add(match.group(1))

    result_map[method] = {
        "bundle_candidates": list(candidates),
        "count": len(candidates)
    }

with open(OUT_MAP, "w", encoding="utf8") as f:
    json.dump(result_map, f, indent=2, ensure_ascii=False)

print(f"[+] Runtime → Bundle карта: {OUT_MAP}")


# ======================================================
# 4. Поиск скрытых функций
# ======================================================
hidden = sorted(list(bundle_funcs - set(result_map.keys())))

with open(OUT_HIDDEN, "w", encoding="utf8") as f:
    json.dump(hidden, f, indent=2, ensure_ascii=False)

print(f"[+] Скрытые/неиспользуемые функции: {OUT_HIDDEN}")


# ======================================================
# 5. Анализ RNG / Seed / Hash / Salt
# ======================================================
rng_report = {
    "seeds": [],
    "salts": [],
    "hashes": [],
    "crashes": [],
    "nonce": [],
}

for evt in rng_events:
    for k, v in evt.items():
        rng_report[k + "s"].append(v)

with open(OUT_RNG, "w", encoding="utf8") as f:
    json.dump(rng_report, f, indent=2, ensure_ascii=False)

print(f"[+] Анализ RNG: {OUT_RNG}")


# ======================================================
# 6. Проверка преждевременного CRASH
# ======================================================
crash_lines = "\n".join(crash_events)

crash_analysis = {
    "crash_mentions_before_finishRound": (
        "finishRound" in crash_lines and "crash" in crash_lines
    ),
    "raw_crash_messages": crash_events[:20],
}

with open(OUT_CRASH, "w", encoding="utf8") as f:
    json.dump(crash_analysis, f, indent=2, ensure_ascii=False)

print(f"[+] Анализ premature crash: {OUT_CRASH}")


# ======================================================
# 7. Поиск уязвимостей
# ======================================================
security_findings = []

if any("seed" in e for e in rng_events):
    security_findings.append("КЛЮЧЕВАЯ УЯЗВИМОСТЬ: seed передаётся клиенту → RNG не серверный → предсказуемый crash.")

if any("salt" in e for e in rng_events):
    security_findings.append("ПРЕДУПРЕЖДЕНИЕ: salt пришёл заранее → возможна подмена/подбор результата.")

if crash_analysis["crash_mentions_before_finishRound"]:
    security_findings.append("КРИТИЧНО: crash приходит раньше finishRound → игра нечестная.")

if len(runtime_methods) < 10:
    security_findings.append("ПРИЗНАК ПЕСОЧНИЦЫ: мало rpc методов → возможно eval/dynamic loader.")


with open(OUT_VULN, "w", encoding="utf8") as f:
    json.dump(security_findings, f, indent=2, ensure_ascii=False)

print(f"[+] Security findings: {OUT_VULN}")


# ======================================================
# 8. Автоматический git-push
# ======================================================
print("[*] Авто‑push: готовлюсь…")

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# git identity (если не установлено)
run('git config user.email "auto@analyzer.local"')
run('git config user.name "UltraDeepAnalyzer"')

# pull перед push
run("git pull --rebase")

# add
run(f"git add {REPORT_DIR}")

# commit
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
run(f'git commit -m "Auto-generated deep analysis {timestamp}"')

# push
push = run("git push origin main")

print(push.stdout)
print(push.stderr)

print("\n[✓] Полный анализ + git push завершён.")