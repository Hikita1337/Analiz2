import re
import ast
import base64
import json
from pathlib import Path
from datetime import datetime

JS_PATH = "2025-12-09_09-42-51-297323.js"
REPORT_DIR = Path("reports")


def read_file(path):
    try:
        return Path(path).read_text(errors="ignore")
    except:
        print(f"[ERROR] Can't read file: {path}")
        return ""


# ---------------------------------------------------------
#  URL / BASE64 / HEX DETECTION
# ---------------------------------------------------------

def detect_urls(text):
    return re.findall(r'https?://[^\s\'"]+', text)


def detect_base64(text):
    b64_regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    found = re.findall(b64_regex, text)
    decoded = []
    for chunk in found:
        try:
            d = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if d.strip():
                decoded.append((chunk, d))
        except:
            pass
    return decoded


def detect_hex_strings(text):
    hex_regex = r'(?:[0-9a-fA-F]{2}){8,}'
    found = re.findall(hex_regex, text)
    decoded = []
    for h in found:
        try:
            d = bytes.fromhex(h).decode("utf-8", errors="ignore")
            if d.strip():
                decoded.append((h, d))
        except:
            pass
    return decoded


# ---------------------------------------------------------
#  FUNCTIONS / CLASSES / IMPORTS / EXPORTS
# ---------------------------------------------------------

def detect_functions(text):
    pattern = r'(function\s+(\w+)|(\w+)\s*=\s*function|\w+\s*=>)'
    funcs = []
    for line in text.splitlines():
        if re.search(pattern, line):
            funcs.append(line.strip())
    return funcs


def detect_class_definitions(text):
    return re.findall(r'class\s+(\w+)', text)


def detect_exports(text):
    return re.findall(r'export\s+(?:default\s+)?(\w+)', text)


def detect_require_import(text):
    imports = re.findall(r'import\s+.*?from\s+[\'"](.*?)[\'"]', text)
    requires = re.findall(r'require\([\'"](.*?)[\'"]\)', text)
    return imports, requires


# ---------------------------------------------------------
#  SUSPICIOUS CODE
# ---------------------------------------------------------

def detect_suspicious(text):
    suspicious = [
        "eval", "Function(", "atob", "btoa", "while(true)",
        "setInterval", "crypto", "fetch", "$.ajax", "XMLHttpRequest"
    ]
    flags = [s for s in suspicious if s in text]
    return flags


# ---------------------------------------------------------
#  OBFUSCATION DETECTION
# ---------------------------------------------------------

def detect_jsfuck(text):
    if re.search(r'[\[\]\(\)\!]{10,}', text):
        return True
    return False


def detect_obfuscator_io(text):
    markers = [
        "_0x",  # частые переменные
        "var _0x", 
        "function(_0x",
        "decodeURIComponent"
    ]
    return any(m in text for m in markers)


# ---------------------------------------------------------
#  SIMPLE VARIABLE DEOBFUSCATION
# ---------------------------------------------------------

def simple_deobfuscate_vars(text):
    assign_regex = r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\'];'
    mapping = dict(re.findall(assign_regex, text))

    # подмена всех вхождений
    for var, val in mapping.items():
        text = text.replace(var, val)
    return text


# ---------------------------------------------------------
#  CALL GRAPH (STATIC)
# ---------------------------------------------------------

def build_call_graph(text):
    functions = re.findall(r'function\s+(\w+)', text)
    call_graph = {f: [] for f in functions}

    for f in functions:
        pattern = rf'{f}\s*\('
        for other in functions:
            if other == f:
                continue
            if re.search(rf'{other}\s*\(', text):  # вызывает другую функцию
                if other not in call_graph[f]:
                    call_graph[f].append(other)

    return call_graph


# ---------------------------------------------------------
#  GENERATE CALL EXAMPLES
# ---------------------------------------------------------

def generate_examples(funcs):
    examples = []
    for f in funcs:
        fname = re.findall(r'function\s+(\w+)', f)
        if not fname:
            fname = re.findall(r'(\w+)\s*=\s*function', f)
        if not fname:
            continue
        name = fname[0]
        examples.append(f"{name}();  // Пример вызова")
    return examples


# ---------------------------------------------------------
#  SAFE VIRTUAL EXECUTION (expr only)
# ---------------------------------------------------------

def safe_eval_expr(expr):
    try:
        node = ast.parse(expr, mode="eval")
        allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant)
        for n in ast.walk(node):
            if not isinstance(n, allowed):
                return "Запрещено для безопасной эмуляции"
        return eval(expr)
    except:
        return "Не удалось выполнить безопасную эмуляцию"


# ---------------------------------------------------------
#  MAIN
# ---------------------------------------------------------

def analyze_js(path):
    text = read_file(path)
    if not text:
        return

    REPORT_DIR.mkdir(exist_ok=True)
    report = {}

    # BASIC METADATA
    report["file"] = path
    report["size"] = len(text)

    # EXTRACTION
    urls = detect_urls(text)
    funcs = detect_functions(text)
    classes = detect_class_definitions(text)
    susp = detect_suspicious(text)
    exports = detect_exports(text)
    b64 = detect_base64(text)
    hexs = detect_hex_strings(text)
    imports, requires = detect_require_import(text)

    report["urls"] = urls
    report["functions"] = funcs
    report["classes"] = classes
    report["suspicious"] = susp
    report["exports"] = exports
    report["imports"] = imports
    report["requires"] = requires
    report["base64"] = b64
    report["hex"] = hexs

    # OBFUSCATION
    report["jsfuck_detected"] = detect_jsfuck(text)
    report["obfuscator_io_detected"] = detect_obfuscator_io(text)

    # SIMPLE DEOBFUSCATION
    report["simple_deobfuscation_preview"] = simple_deobfuscate_vars(text)[:500]

    # CALL GRAPH
    report["call_graph"] = build_call_graph(text)

    # EXAMPLES
    report["call_examples"] = generate_examples(funcs)

    # SAFE EVAL TEST
    report["safe_eval_example"] = safe_eval_expr("2 + 3 * 4")

    # SAVE REPORT
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_file = REPORT_DIR / f"report_{ts}.json"
    out_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print(f"[OK] Отчёт сохранён: {out_file}")


if __name__ == "__main__":
    analyze_js(JS_PATH)