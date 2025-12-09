import re
import ast
import base64
import json
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import subprocess

# ---------------- CONFIG ----------------
JS_PATH = "2025-12-09_09-42-51-297323.js"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
BASE64_LIMIT = 100
HEX_LIMIT = 100

# ---------------- UTIL ----------------
def read_file(path):
    try:
        text = Path(path).read_text(errors="ignore")
        print(f"[*] Файл '{path}' прочитан, размер: {len(text)} байт")
        return text
    except:
        print(f"[ERROR] Не удалось прочитать файл: {path}")
        return ""

# ---------------- DETECTORS ----------------
def detect_urls(text):
    return list(set(re.findall(r'https?://[^\s\'"]+', text)))

def detect_base64(text, limit=BASE64_LIMIT):
    b64_regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    found = re.findall(b64_regex, text)[:limit]
    decoded = []
    for chunk in tqdm(found, desc="Base64 декодирование"):
        try:
            d = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if d.strip():
                decoded.append((chunk, d))
        except:
            pass
    return list({orig: dec for orig, dec in decoded}.items())

def detect_hex_strings(text, limit=HEX_LIMIT):
    hex_regex = r'(?:[0-9a-fA-F]{2}){8,}'
    found = re.findall(hex_regex, text)[:limit]
    decoded = []
    for h in tqdm(found, desc="HEX декодирование"):
        try:
            d = bytes.fromhex(h).decode("utf-8", errors="ignore")
            if d.strip():
                decoded.append((h, d))
        except:
            pass
    return list({orig: dec for orig, dec in decoded}.items())

def detect_functions(text):
    pattern = r'(function\s+(\w+)|(\w+)\s*=\s*function|\w+\s*=>)'
    funcs = [line.strip() for line in text.splitlines() if re.search(pattern, line)]
    return list(dict.fromkeys(funcs))  # уникальные функции

def detect_class_definitions(text):
    return list(set(re.findall(r'class\s+(\w+)', text)))

def detect_exports(text):
    return list(set(re.findall(r'export\s+(?:default\s+)?(\w+)', text)))

def detect_require_import(text):
    imports = list(set(re.findall(r'import\s+.*?from\s+[\'"](.*?)[\'"]', text)))
    requires = list(set(re.findall(r'require\([\'"](.*?)[\'"]\)', text)))
    return imports, requires

def detect_suspicious(text):
    suspicious = ["eval", "Function(", "atob", "btoa", "while(true)",
                  "setInterval", "crypto", "fetch", "$.ajax", "XMLHttpRequest"]
    return [s for s in suspicious if s in text]

def detect_jsfuck(text):
    return bool(re.search(r'[\[\]\(\)\!]{10,}', text))

def detect_obfuscator_io(text):
    markers = ["_0x", "var _0x", "function(_0x", "decodeURIComponent"]
    return any(m in text for m in markers)

def simple_deobfuscate_vars(text):
    assign_regex = r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\'];'
    mapping = dict(re.findall(assign_regex, text))
    for var, val in mapping.items():
        text = text.replace(var, val)
    return text

# ---------------- CALL GRAPH ----------------
def build_call_graph_unique(text):
    functions = list(set(re.findall(r'function\s+(\w+)', text)))
    call_graph = {f: set() for f in functions}

    # разбиваем текст на строки
    lines = text.splitlines()
    func_lines = {}
    current_func = None
    for line in lines:
        m = re.match(r'function\s+(\w+)', line)
        if m:
            current_func = m.group(1)
            func_lines[current_func] = []
        if current_func:
            func_lines[current_func].append(line)
        if line.strip() == '}':
            current_func = None

    # поиск вызовов внутри тела функции
    for i, f in enumerate(functions):
        if i % 50 == 0:
            print(f"[*] Построение графа: {i}/{len(functions)} функций")
        body = "\n".join(func_lines.get(f, []))
        for other in functions:
            if f != other and re.search(rf'\b{other}\s*\(', body):
                call_graph[f].add(other)

    return {f: list(callees) for f, callees in call_graph.items()}

# ---------------- SAFE EVAL ----------------
def safe_eval_expr(expr):
    try:
        node = ast.parse(expr, mode="eval")
        allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant)
        for n in ast.walk(node):
            if not isinstance(n, allowed):
                return "Запрещено для безопасной эмуляции"
        return eval(expr)
    except:
        return "Ошибка безопасной эмуляции"

# ---------------- V8 SANDBOX ----------------
def run_js_sandbox(js_code):
    try:
        result = subprocess.run(
            ["node", "-e", js_code],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.stdout.strip() or "Нет вывода"
    except subprocess.TimeoutExpired:
        return "Время выполнения превышено"
    except Exception as e:
        return f"Ошибка: {e}"

# ---------------- MAIN ----------------
def analyze_js(path):
    text = read_file(path)
    if not text:
        return

    report = {}
    report["file"] = path
    report["size"] = len(text)

    print("[*] Детектируем URL...")
    urls = detect_urls(text)
    print(f"[*] Найдено URL: {len(urls)}")

    print("[*] Детектируем Base64...")
    b64 = detect_base64(text)

    print("[*] Детектируем HEX...")
    hexs = detect_hex_strings(text)

    print("[*] Детектируем функции и классы...")
    funcs = detect_functions(text)
    classes = detect_class_definitions(text)

    print("[*] Детектируем экспорты и импорты...")
    exports = detect_exports(text)
    imports, requires = detect_require_import(text)

    print("[*] Детектируем подозрительные конструкции...")
    susp = detect_suspicious(text)

    report.update({
        "urls": urls,
        "base64": b64,
        "hex": hexs,
        "functions": funcs,
        "classes": classes,
        "exports": exports,
        "imports": imports,
        "requires": requires,
        "suspicious": susp,
        "jsfuck_detected": detect_jsfuck(text),
        "obfuscator_io_detected": detect_obfuscator_io(text),
        "simple_deobfuscation_preview": simple_deobfuscate_vars(text)[:500]
    })

    print("[*] Строим граф вызовов...")
    call_graph = build_call_graph_unique(text)
    report["call_graph"] = call_graph

    # V8 sandbox test
    if funcs:
        sample_func = funcs[0].split()[1].split('(')[0] if "function" in funcs[0] else "console.log('sample')"
        report["v8_sandbox_test"] = run_js_sandbox(f"{sample_func}; console.log('sandbox OK');")

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_file = REPORT_DIR / f"report_{ts}.json"
    json_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"[*] JSON-отчёт сохранён: {json_file}")

    # HTML отчёт
    html_file = REPORT_DIR / f"report_{ts}.html"
    html_content = f"""
<html>
<head><title>JS Анализ отчёт</title></head>
<body>
<h1>Отчёт по файлу {path}</h1>
<p>Размер файла: {len(text)} байт</p>

<h2>Функции</h2><pre>{funcs}</pre>

<h2>Классы</h2><pre>{classes}</pre>

<h2>Подозрительные конструкции</h2><pre>{susp}</pre>

<h2>URLs</h2><pre>{urls}</pre>

<h2>Граф вызовов</h2><pre>{json.dumps(call_graph, indent=2)}</pre>

<h2>V8 Sandbox тест</h2><pre>{report.get('v8_sandbox_test')}</pre>
</body>
</html>
"""
    html_file.write_text(html_content, encoding="utf-8")
    print(f"[*] HTML-отчёт сохранён: {html_file}")

if __name__ == "__main__":
    analyze_js(JS_PATH)