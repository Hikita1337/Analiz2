import re, ast, base64, json, subprocess, sys, os
from pathlib import Path
from datetime import datetime
from tqdm import tqdm

# ---------------- CONFIG ----------------
JS_PATHS = ["2025-12-09_09-42-51-297323.js","2025-12-09_09-43-26-128433.js"]
TRAFFIC_PATH = "bigdump.txt"
REPORT_DIR = Path("deep_reports"); REPORT_DIR.mkdir(exist_ok=True)
BASE64_LIMIT = 100; HEX_LIMIT = 100

# ---------------- DEPENDENCY ----------------
def ensure_package(pkg):
    import importlib
    try: importlib.import_module(pkg)
    except ImportError:
        subprocess.check_call([sys.executable,"-m","pip","install",pkg])
ensure_package("tqdm")
ensure_package("graphviz")

# ---------------- UTIL ----------------
def read_file(path):
    try:
        text = Path(path).read_text(errors="ignore")
        print(f"[*] Файл '{path}' прочитан, размер: {len(text)} байт")
        return text
    except: return ""

# ---------------- DETECTORS ----------------
def detect_urls(text): return list(set(re.findall(r'https?://[^\s\'"]+', text)))
def detect_base64(text, limit=BASE64_LIMIT):
    b64_regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    found = re.findall(b64_regex, text)[:limit]; decoded=[]
    for chunk in tqdm(found, desc="Base64 декодирование"):
        try: d = base64.b64decode(chunk).decode("utf-8", errors="ignore"); decoded.append((chunk,d)) if d.strip() else None
        except: pass
    return list({o:d for o,d in decoded}.items())
def detect_hex_strings(text, limit=HEX_LIMIT):
    hex_regex = r'(?:[0-9a-fA-F]{2}){8,}'
    found = re.findall(hex_regex, text)[:limit]; decoded=[]
    for h in tqdm(found, desc="HEX декодирование"):
        try: d = bytes.fromhex(h).decode("utf-8", errors="ignore"); decoded.append((h,d)) if d.strip() else None
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
def detect_obfuscator_io(text): return any(m in text for m in ["_0x","var _0x","function(_0x","decodeURIComponent"])
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

# ---------------- PF / RNG / CRASH ----------------
def analyze_rng_crash(websocket_payloads):
    rng_report = {"crash":[], "nonces":[], "serverSeed":[], "clientSeed":[], "salt":[]}
    for payload in websocket_payloads:
        for k in rng_report.keys():
            if k in payload: rng_report[k].append(payload)
    return rng_report

# ---------------- GIT PUSH ----------------
def git_add_commit_push(files, commit_msg="Авто-отчёт"):
    try:
        subprocess.run(["git","add"]+files,check=True)
        subprocess.run(["git","commit","-m",commit_msg],check=True)
        subprocess.run(["git","pull","--rebase"],check=True)
        subprocess.run(["git","push"],check=True)
        with open(REPORT_DIR/"git_push_log.txt","w",encoding="utf-8") as f: f.write("Пуш выполнен успешно\n")
        print("[*] Файлы успешно запушены в репозиторий")
    except subprocess.CalledProcessError as e: print(f"[ERROR] Git ошибка: {e}")

# ---------------- ULTRA ANALYZER ----------------
def ultra_analyze(js_paths, traffic_path):
    report={}
    combined_js_text=""
    for path in js_paths: combined_js_text += read_file(path)+"\n"
    traffic_text=read_file(traffic_path)
    websocket_payloads=re.findall(r'\{.*?\}',traffic_text,re.DOTALL)

    report["urls"]=detect_urls(combined_js_text)
    report["base64"]=detect_base64(combined_js_text)
    report["hex"]=detect_hex_strings(combined_js_text)
    report["functions"]=detect_functions(combined_js_text)
    report["classes"]=detect_class_definitions(combined_js_text)
    report["exports"]=detect_exports(combined_js_text)
    report["imports"],report["requires"]=detect_require_import(combined_js_text)
    report["suspicious"]=detect_suspicious(combined_js_text)
    report["jsfuck_detected"]=detect_jsfuck(combined_js_text)
    report["obfuscator_io_detected"]=detect_obfuscator_io(combined_js_text)
    report["simple_deobfuscation_preview"]=simple_deobfuscate_vars(combined_js_text)[:500]
    report["call_graph"]=build_call_graph_unique(combined_js_text)
    report["function_event_mapping"]=link_functions_to_events(combined_js_text, websocket_payloads)
    report["pf_rng_crash"]=analyze_rng_crash(websocket_payloads)
    
    ts=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_file = REPORT_DIR/f"pf_anomaly_report_{ts}.json"
    html_file = REPORT_DIR/f"pf_anomaly_report_{ts}.html"
    json_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    html_content=f"""
<html>
<head><meta charset="UTF-8"><title>PF Ультра-анализ JS</title></head>
<body>
<h1>PF Отчёт по файлам {js_paths+[traffic_path]}</h1>
<h2>Функции</h2><pre>{report['functions']}</pre>
<h2>Скрытые функции</h2><pre>{report['suspicious']}</pre>
<h2>RNG / Crash / Salt / Seed</h2><pre>{json.dumps(report['pf_rng_crash'], indent=2)}</pre>
<h2>Call Graph</h2><pre>{json.dumps(report['call_graph'], indent=2)}</pre>
<h2>Function-Event Mapping</h2><pre>{json.dumps(report['function_event_mapping'], indent=2)}</pre>
</body>
</html>
"""
    html_file.write_text(html_content, encoding="utf-8")

    print(f"[*] JSON-отчёт: {json_file}")
    print(f"[*] HTML-отчёт: {html_file}")
    
    git_add_commit_push([str(json_file), str(html_file)], commit_msg=f"PF Анализ {ts}")

if __name__=="__main__":
    ultra_analyze(JS_PATHS, TRAFFIC_PATH)