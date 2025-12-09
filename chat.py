import re
import ast
import base64
import json
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import subprocess
import sys

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
    urls = re.findall(r'https?://[^\s\'"]+', text)
    print(f"[*] Найдено URL: {len(urls)}")
    return urls

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
    print(f"[*] Декодировано Base64: {len(decoded)}")
    return decoded

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
    print(f"[*] Декодировано HEX: {len(decoded)}")
    return decoded

def detect_functions(text):
    pattern = r'(function\s+(\w+)|(\w+)\s*=\s*function|\w+\s*=>)'
    funcs = [line.strip() for line in text.splitlines() if re.search(pattern, line)]
    print(f"[*] Найдено функций: {len(funcs)}")
    return funcs

def detect_class_definitions(text):
    classes = re.findall(r'class\s+(\w+)', text)
    print(f"[*] Найдено классов: {len(classes)}")
    return classes

def detect_exports(text):
    exports = re.findall(r'export\s+(?:default\s+)?(\w+)', text)
    print(f"[*] Найдено exports: {len(exports)}")
    return exports

def detect_require_import(text):
    imports = re.findall(r'import\s+.*?from\s+[\'"](.*?)[\'"]', text)
    requires = re.findall(r'require\([\'"](.*?)[\'"]\)', text)
    print(f"[*] Найдено import: {len(imports)}, require: {len(requires)}")
    return imports, requires

def detect_suspicious(text):
    suspicious = ["eval", "Function(", "atob", "btoa", "while(true)",
                  "setInterval", "crypto", "fetch", "$.ajax", "XMLHttpRequest"]
    flags = [s for s in suspicious if s in text]
    print(f"[*] Найдено подозрительных конструкций: {len(flags)}")
    return flags

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
def build_call_graph(text):
    functions = re.findall(r'function\s+(\w+)', text)
    call_graph = {f: [] for f in functions}
    for i, f in enumerate(functions):
        if i % 10 == 0:
            print(f"[*] Построение графа: {i}/{len(functions)} функций")
        for other in functions:
            if f != other and re.search(rf'{other}\s*\(', text):
                if other not in call_graph[f]:
                    call_graph[f].append(other)
    print(f"[*] Граф вызовов построен для {len(call_graph)} функций")
    return call_graph

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
    """
    Безопасный запуск JS через Node/V8 sandbox.
    В Codespaces должен быть установлен node.js
    """
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

    urls = detect_urls(text)
    funcs = detect_functions(text)
    classes = detect_class_definitions(text)
    susp = detect_suspicious(text)
    exports = detect_exports(text)
    b64 = detect_base64(text)
    hexs = detect_hex_strings(text)
    imports, requires = detect_require_import(text)

    report.update({
        "urls": urls,
        "functions": funcs,
        "classes": classes,
        "suspicious": susp,
        "exports": exports,
        "imports": imports,
        "requires": requires,
        "base64": b64,
        "hex": hexs,
        "jsfuck_detected": detect_jsfuck(text),
        "obfuscator_io_detected": detect_obfuscator_io(text),
        "simple_deobfuscation_preview": simple_deobfuscate_vars(text)[:500]
    })

    call_graph = build_call_graph(text)
    report["call_graph"] = call_graph

    # Пример безопасного запуска JS
    if funcs:
        sample_func = funcs[0].split()[1].split('(')[0] if "function" in funcs[0] else "console.log('sample')"
        report["v8_sandbox_test"] = run_js_sandbox(f"{sample_func}; console.log('sandbox OK');")

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_file = REPORT_DIR / f"report_{ts}.json"
    json_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"[*] JSON-отчёт сохранён: {json_file}")

if __name__ == "__main__":
    analyze_js(JS_PATH)