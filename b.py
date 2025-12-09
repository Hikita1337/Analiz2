import re, ast, base64, json, subprocess, sys, os
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

# ---------------- CONFIG ----------------
JS_PATHS = ["2025-12-09_09-42-51-297323.js","2025-12-09_09-43-26-128433.js"]
TRAFFIC_PATH = "bigdump.txt"
REPORT_DIR = Path("deep_reports"); REPORT_DIR.mkdir(exist_ok=True)
BASE64_LIMIT = 100
HEX_LIMIT = 100

# ---------------- UTIL ----------------
def read_file(path):
    try:
        text = Path(path).read_text(errors="ignore")
        print(f"[*] Файл '{path}' прочитан, размер: {len(text)} байт")
        return text
    except:
        return ""

# ---------------- DETECTORS ----------------
def detect_urls(text): return list(set(re.findall(r'https?://[^\s\'"]+', text)))
def detect_base64(text, limit=BASE64_LIMIT):
    b64_regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    found = re.findall(b64_regex, text)[:limit]
    decoded=[]
    for chunk in tqdm(found, desc="Base64 декодирование"):
        try: d=base64.b64decode(chunk).decode("utf-8",errors="ignore"); decoded.append((chunk,d)) if d.strip() else None
        except: pass
    return list({o:d for o,d in decoded}.items())
def detect_hex_strings(text, limit=HEX_LIMIT):
    hex_regex = r'(?:[0-9a-fA-F]{2}){8,}'
    found=re.findall(hex_regex,text)[:limit]; decoded=[]
    for h in tqdm(found, desc="HEX декодирование"):
        try: d=bytes.fromhex(h).decode("utf-8",errors="ignore"); decoded.append((h,d)) if d.strip() else None
        except: pass
    return list({o:d for o,d in decoded}.items())
def detect_functions(text):
    pattern=r'(function\s+(\w+)|(\w+)\s*=\s*function|\w+\s*=>)'
    return list(dict.fromkeys([l.strip() for l in text.splitlines() if re.search(pattern,l)]))
def detect_class_definitions(text): return list(set(re.findall(r'class\s+(\w+)',text)))
def detect_exports(text): return list(set(re.findall(r'export\s+(?:default\s+)?(\w+)',text)))
def detect_require_import(text):
    imports=list(set(re.findall(r'import\s+.*?from\s+[\'"](.*?)[\'"]',text)))
    requires=list(set(re.findall(r'require\([\'"](.*?)[\'"]\)',text)))
    return imports,requires
def detect_suspicious(text):
    suspicious=["eval","Function(","atob","btoa","while(true)","setInterval","crypto","fetch","$.ajax","XMLHttpRequest"]
    return [s for s in suspicious if s in text]
def detect_jsfuck(text): return bool(re.search(r'[\[\]\(\)\!]{10,}',text))
def detect_obfuscator_io(text): return any(m in text for m in ["_0x","var _0x","function(_0x"])
def simple_deobfuscate_vars(text):
    assign_regex=r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\'];'
    mapping=dict(re.findall(assign_regex,text))
    for var,val in mapping.items(): text=text.replace(var,val)
    return text

# ---------------- CALL GRAPH ----------------
def build_call_graph_unique(text):
    functions=list(set(re.findall(r'function\s+(\w+)',text)))
    call_graph={f:set() for f in functions}
    lines=text.splitlines(); func_lines={}; current_func=None
    for line in lines:
        m=re.match(r'function\s+(\w+)',line)
        if m: current_func=m.group(1); func_lines[current_func]=[]
        if current_func: func_lines[current_func].append(line)
        if line.strip()=='}': current_func=None
    for i,f in enumerate(functions):
        if i%50==0: print(f"[*] Построение графа: {i}/{len(functions)} функций")
        body="\n".join(func_lines.get(f,[]))
        for other in functions:
            if f!=other and re.search(rf'\b{other}\s*\(',body): call_graph[f].add(other)
    return {f:list(c) for f,c in call_graph.items()}

# ---------------- SAFE EVAL ----------------
def safe_eval_expr(expr):
    try:
        node=ast.parse(expr,mode="eval"); allowed=(ast.Expression,ast.BinOp,ast.UnaryOp,ast.Num,ast.Constant)
        for n in ast.walk(node): 
            if not isinstance(n,allowed): return "Запрещено для безопасной эмуляции"
        return eval(expr)
    except: return "Ошибка безопасной эмуляции"

# ---------------- V8 SANDBOX ----------------
def run_js_sandbox(js_code):
    try:
        result=subprocess.run(["node","-e",js_code],capture_output=True,text=True,timeout=2)
        return result.stdout.strip() or "Нет вывода"
    except subprocess.TimeoutExpired: return "Время выполнения превышено"
    except Exception as e: return f"Ошибка: {e}"

# ---------------- FUNCTION-EVENT LINK ----------------
def link_functions_to_events(js_text, websocket_payloads):
    mapping={}
    funcs=detect_functions(js_text)
    for f in tqdm(funcs, desc="Привязка функций к событиям"):
        mapping[f]=[]
        for payload in websocket_payloads:
            if f.split()[1].split('(')[0] in payload: mapping[f].append(payload)
    return mapping

# ---------------- PF PREDICTIVE ANALYZER ----------------
def pf_predictive_analyzer(websocket_payloads):
    result = {
        "early_crash": [],
        "early_hash": [],
        "early_salt": [],
        "early_seed": [],
        "early_serverSeed": [],
        "raw_candidates": []
    }
    crash_pattern = re.compile(r'(\d+\.\d{1,4})')
    hash_pattern = re.compile(r'\b[a-f0-9]{64}\b')
    hexlike_pattern = re.compile(r'\b[a-f0-9]{16,}\b')
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')
    seen_round_end = False
    for idx, payload in enumerate(websocket_payloads):
        text = payload
        result["raw_candidates"].append({"index": idx, "payload": text[:500]})
        if any(x in text.lower() for x in ["end", "finish", "round_end", "complete"]):
            seen_round_end = True
        for m in crash_pattern.findall(text):
            try:
                v = float(m)
                if v > 1.0 and not seen_round_end:
                    result["early_crash"].append({"index": idx, "value": v, "payload": text[:500]})
            except: pass
        for h in hash_pattern.findall(text):
            if not seen_round_end:
                result["early_hash"].append({"index": idx, "hash": h, "payload": text[:500]})
        candidates = hexlike_pattern.findall(text) + base64_pattern.findall(text)
        for c in candidates:
            L = len(c)
            if not seen_round_end:
                if 8 <= L <= 32: result["early_salt"].append({"index": idx,"salt":c,"payload":text[:500]})
                if 32 < L <= 64: result["early_seed"].append({"index": idx,"seed":c,"payload":text[:500]})
                if L > 64: result["early_serverSeed"].append({"index": idx,"serverSeed":c,"payload":text[:500]})
    return result

# ---------------- GIT PUSH ----------------
def git_add_commit_push(files, commit_msg="Авто-отчёт"):
    try:
        subprocess.run(["git","add"]+files,check=True)
        subprocess.run(["git","commit","-m",commit_msg],check=True)
        subprocess.run(["git","pull","--rebase"],check=True)
        subprocess.run(["git","push"],check=True)
        print("[*] Файлы успешно запушены в репозиторий")
    except subprocess.CalledProcessError as e: print(f"[ERROR] Git ошибка: {e}")

# ---------------- ULTRA ANALYZER ----------------
def ultra_analyze_with_progress(js_paths, traffic_path):
    steps=["Чтение файлов","Детектируем URL","Детектируем Base64","Детектируем HEX",
           "Детектируем функции и классы","Детектируем экспорты и импорты","Детектируем подозрительные конструкции",
           "Строим граф вызовов","Привязываем функции к событиям WebSocket/трафика",
           "V8 Sandbox тест","Сохраняем отчёты"]
    report={}
    combined_js_text=""
    for path in js_paths: combined_js_text+=read_file(path)+"\n"
    traffic_text=read_file(traffic_path)
    websocket_payloads=re.findall(r'\{.*?\}',traffic_text,re.DOTALL)
    # ---- DETECTORS ----
    report["urls"]=detect_urls(combined_js_text)
    report["base64"]=detect_base64(combined_js_text)
    report["hex"]=detect_hex_strings(combined_js_text)
    report["functions"]=list(dict.fromkeys(detect_functions(combined_js_text))) # remove duplicates
    report["classes"]=detect_class_definitions(combined_js_text)
    report["exports"]=detect_exports(combined_js_text)
    report["imports"],report["requires"]=detect_require_import(combined_js_text)
    report["suspicious"]=detect_suspicious(combined_js_text)
    report["jsfuck_detected"]=detect_jsfuck(combined_js_text)
    report["obfuscator_io_detected"]=detect_obfuscator_io(combined_js_text)
    report["simple_deobfuscation_preview"]=simple_deobfuscate_vars(combined_js_text)[:500]
    report["call_graph"]=build_call_graph_unique(combined_js_text)
    report["function_event_mapping"]=link_functions_to_events(combined_js_text,websocket_payloads)
    if report["functions"]:
        sample_func=report["functions"][0].split()[1].split('(')[0] if "function" in report["functions"][0] else "console.log('sample')"
        report["v8_sandbox_test"]=run_js_sandbox(f"{sample_func}; console.log('sandbox OK');")
    # ---- PF PREDICTIVE ANALYSIS ----
    report["pf_predictive_analysis"] = pf_predictive_analyzer(websocket_payloads)
    # ---- SAVE JSON ----
    ts=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_file=REPORT_DIR/f"ultra_report_{ts}.json"
    json_file.write_text(json.dumps(report,indent=2,ensure_ascii=False))
    print(f"[*] JSON-отчёт сохранён: {json_file}")
    git_add_commit_push([str(json_file)],commit_msg=f"Отчёт {ts}")

if __name__=="__main__":
    ultra_analyze_with_progress(JS_PATHS,TRAFFIC_PATH)