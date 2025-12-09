import re, ast, base64, json, subprocess, sys
from pathlib import Path
from datetime import datetime

# ---------------- CONFIG ----------------
JS_PATHS = ["2025-12-09_09-42-51-297323.js", "2025-12-09_09-43-26-128433.js"]
TRAFFIC_PATH = "bigdump.txt"
REPORT_DIR = Path("reports"); REPORT_DIR.mkdir(exist_ok=True)
BASE64_LIMIT = 100; HEX_LIMIT = 100

# ---------------- DEPENDENCY ----------------
def ensure_package(pkg):
    import importlib
    try: importlib.import_module(pkg)
    except ImportError:
        subprocess.check_call([sys.executable,"-m","pip","install",pkg])

ensure_package("tqdm")
ensure_package("graphviz")
from tqdm import tqdm

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
    found = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', text)[:limit]
    decoded, seen = [], set()
    for chunk in tqdm(found, desc="Base64 декодирование"):
        try:
            d = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if d.strip() and d not in seen:
                decoded.append((chunk,d))
                seen.add(d)
        except: pass
    return decoded

def detect_hex_strings(text, limit=HEX_LIMIT):
    found = re.findall(r'(?:[0-9a-fA-F]{2}){8,}', text)[:limit]
    decoded, seen = [], set()
    for h in tqdm(found, desc="HEX декодирование"):
        try:
            d = bytes.fromhex(h).decode("utf-8", errors="ignore")
            if d.strip() and d not in seen:
                decoded.append((h,d))
                seen.add(d)
        except: pass
    return decoded

def detect_functions(text):
    pattern = r'(function\s+(\w+)|(\w+)\s*=\s*function|\w+\s*=>)'
    return list(dict.fromkeys([l.strip() for l in text.splitlines() if re.search(pattern,l)]))

def detect_class_definitions(text): return list(set(re.findall(r'class\s+(\w+)',text)))
def detect_exports(text): return list(set(re.findall(r'export\s+(?:default\s+)?(\w+)',text)))
def detect_require_import(text):
    imports = list(set(re.findall(r'import\s+.*?from\s+[\'"](.*?)[\'"]',text)))
    requires = list(set(re.findall(r'require\([\'"](.*?)[\'"]\)',text)))
    return imports, requires
def detect_suspicious(text):
    suspicious = ["eval","Function(","atob","btoa","while(true)","setInterval","crypto","fetch","$.ajax","XMLHttpRequest"]
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
    # преобразуем множества в списки
    return {f:list(c) for f,c in call_graph.items()}

# ---------------- SAFE EVAL ----------------
def safe_eval_expr(expr):
    try:
        node=ast.parse(expr,mode="eval")
        allowed=(ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant)
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
    mapping = {}
    funcs = detect_functions(js_text)
    for f in tqdm(funcs, desc="Привязка функций к событиям"):
        mapping[f] = []
        fname = f.split()[1].split('(')[0] if "function" in f else f
        for payload in websocket_payloads:
            if fname in payload and payload not in mapping[f]:
                mapping[f].append(payload)
    return mapping

# ---------------- GIT PUSH ----------------
def git_add_commit_push(files, commit_msg="Авто-отчёт"):
    try:
        subprocess.run(["git","add"]+files,check=True)
        subprocess.run(["git","commit","-m",commit_msg],check=True)
        subprocess.run(["git","pull","--rebase"],check=True)
        subprocess.run(["git","push"],check=True)
        print("[*] Файлы успешно запушены в репозиторий")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Git ошибка: {e}")

# ---------------- ULTRA ANALYZER ----------------
def ultra_analyze(js_paths, traffic_path):
    steps=["Чтение файлов","Детектируем URL","Детектируем Base64","Детектируем HEX",
           "Детектируем функции и классы","Детектируем экспорты и импорты","Детектируем подозрительные конструкции",
           "Строим граф вызовов","Привязываем функции к событиям WebSocket/трафика",
           "V8 Sandbox тест","Сохраняем отчёты"]
    report = {}
    from tqdm import tqdm
    with tqdm(total=len(steps), desc="Прогресс анализа", ncols=100) as pbar:
        combined_js_text = ""
        for path in js_paths: combined_js_text += read_file(path) + "\n"
        traffic_text = read_file(traffic_path)
        # уникальные JSON payloads из трафика
        raw_payloads = re.findall(r'\{.*?\}', traffic_text, re.DOTALL)
        websocket_payloads = []
        seen_payloads = set()
        for p in raw_payloads:
            normalized = re.sub(r'\s+', '', p)
            if normalized not in seen_payloads:
                websocket_payloads.append(p)
                seen_payloads.add(normalized)
        pbar.update(1)
        report["urls"] = list(set(detect_urls(combined_js_text))); pbar.update(1)
        report["base64"] = detect_base64(combined_js_text); pbar.update(1)
        report["hex"] = detect_hex_strings(combined_js_text); pbar.update(1)
        report["functions"] = detect_functions(combined_js_text)
        report["classes"] = detect_class_definitions(combined_js_text); pbar.update(1)
        report["exports"] = detect_exports(combined_js_text)
        report["imports"], report["requires"] = detect_require_import(combined_js_text); pbar.update(1)
        report["suspicious"] = detect_suspicious(combined_js_text)
        report["jsfuck_detected"] = detect_jsfuck(combined_js_text)
        report["obfuscator_io_detected"] = detect_obfuscator_io(combined_js_text)
        report["simple_deobfuscation_preview"] = simple_deobfuscate_vars(combined_js_text)[:500]; pbar.update(1)
        report["call_graph"] = build_call_graph_unique(combined_js_text); pbar.update(1)
        report["function_event_mapping"] = link_functions_to_events(combined_js_text, websocket_payloads); pbar.update(1)
        if report["functions"]:
            sample_func = report["functions"][0].split()[1].split('(')[0] if "function" in report["functions"][0] else "console.log('sample')"
            report["v8_sandbox_test"] = run_js_sandbox(f"{sample_func}; console.log('sandbox OK');")
        pbar.update(1)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        json_file = REPORT_DIR / f"ultra_report_{ts}.json"
        html_file = REPORT_DIR / f"ultra_report_{ts}.html"
        json_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        html_content = f"""
<html>
<head><meta charset="UTF-8"><title>Ультра-анализ JS</title></head>
<body>
<h1>Отчёт по файлам {js_paths+[traffic_path]}</h1>
<p>Общий размер: {sum(len(read_file(p)) for p in js_paths)+len(traffic_text)} байт</p>
<h2>Функции</h2><pre>{report['functions']}</pre>
<h2>Классы</h2><pre>{report['classes']}</pre>
<h2>Подозрительные конструкции</h2><pre>{report['suspicious']}</pre>
<h2>URLs</h2><pre>{report['urls']}</pre>
<h2>Граф вызовов</h2><pre>{json.dumps(report['call_graph'],indent=2)}</pre>
<h2>Привязка функций к событиям</h2><pre>{json.dumps(report['function_event_mapping'],indent=2)}</pre>
<h2>V8 Sandbox тест</h2><pre>{report.get('v8_sandbox_test')}</pre>
</body>
</html>
"""
        html_file.write_text(html_content, encoding="utf-8"); pbar.update(1)
    print(f"[*] JSON-отчёт сохранён: {json_file}")
    print(f"[*] HTML-отчёт сохранён: {html_file}")
    git_add_commit_push([str(json_file), str(html_file)], commit_msg=f"Отчёт {ts}")

if __name__=="__main__":
    ultra_analyze(JS_PATHS, TRAFFIC_PATH)