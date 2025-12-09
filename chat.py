#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import ast
import base64
import json
import subprocess
from pathlib import Path
from datetime import datetime
from graphviz import Digraph

JS_PATH = "2025-12-09_09-42-51-297323.js"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# ================================================
# READ FILE
# ================================================

def read_file(path):
    try:
        return Path(path).read_text(errors="ignore")
    except:
        return ""


# ================================================
# DETECTORS
# ================================================

def detect_urls(text):
    return re.findall(r'https?://[^\s\'"]+', text)

def detect_base64(text):
    regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    out = []
    for chunk in re.findall(regex, text):
        try:
            decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if decoded.strip():
                out.append((chunk, decoded))
        except:
            pass
    return out

def detect_hex_strings(text):
    regex = r'(?:[0-9a-fA-F]{2}){8,}'
    out = []
    for h in re.findall(regex, text):
        try:
            decoded = bytes.fromhex(h).decode("utf-8", errors="ignore")
            if decoded.strip():
                out.append((h, decoded))
        except:
            pass
    return out

def detect_functions(text):
    pattern = r'(function\s+(\w+)|(\w+)\s*=\s*function|\w+\s*=>)'
    funcs = []
    for l in text.splitlines():
        if re.search(pattern, l):
            funcs.append(l.strip())
    return funcs

def detect_class_definitions(text):
    return re.findall(r'class\s+(\w+)', text)

def detect_exports(text):
    return re.findall(r'export\s+(?:default\s+)?(\w+)', text)

def detect_require_import(text):
    imports = re.findall(r'import\s+.*?from\s+[\'"](.*?)[\'"]', text)
    requires = re.findall(r'require\([\'"](.*?)[\'"]\)', text)
    return imports, requires

def detect_suspicious(text):
    suspects = ["eval", "Function(", "atob", "btoa", "while(true)",
                "setInterval", "crypto", "fetch", "$.ajax", "XMLHttpRequest"]
    return [s for s in suspects if s in text]

def detect_jsfuck(text):
    return bool(re.search(r'[\[\]\(\)\!]{12,}', text))

def detect_obfuscator_io(text):
    markers = ["_0x", "var _0x", "function(_0x", "decodeURIComponent"]
    return any(m in text for m in markers)

# ================================================
# SIMPLE VAR DEOBFUSCATION
# ================================================

def simple_deobfuscate_vars(text):
    regex = r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\'];'
    mapping = dict(re.findall(regex, text))
    for var, val in mapping.items():
        text = text.replace(var, val)
    return text

# ================================================
# CALL GRAPH
# ================================================

def build_call_graph(text):
    funcs = re.findall(r'function\s+(\w+)', text)
    graph = {f: [] for f in funcs}

    for f in funcs:
        for callee in funcs:
            if f != callee:
                if re.search(rf'\b{callee}\s*\(', text):
                    graph[f].append(callee)

    return graph


def render_call_graph_png(call_graph, output_path):
    g = Digraph("callgraph", format="png")
    g.attr(rankdir="LR")

    for f in call_graph:
        g.node(f)

    for f, calls in call_graph.items():
        for c in calls:
            g.edge(f, c)

    g.render(output_path, cleanup=True)


# ================================================
# EXECUTION (SAFE SANDBOX USING V8)
# ================================================

def init_v8_env():
    # создаёт временный JS-файл для sandbox исполнения
    node_js = '''
const ivm = require('isolated-vm');
const fs = require('fs');

async function run() {
    const code = fs.readFileSync(process.argv[2], 'utf8');

    let isolate = new ivm.Isolate({ memoryLimit: 16 });
    let context = await isolate.createContext();

    let script;
    try {
        script = await isolate.compileScript(code);
        let result = await script.run(context, { timeout: 100 });
        console.log(JSON.stringify({ok: true, result: String(result)}));
    } catch (e) {
        console.log(JSON.stringify({ok: false, error: e.message}));
    }
}
run();
'''
    Path("v8_runner.js").write_text(node_js)


def run_js_sandbox(code):
    temp = Path("temp_exec.js")
    temp.write_text(code)

    try:
        p = subprocess.Popen(
            ["node", "v8_runner.js", str(temp)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = p.communicate(timeout=2)
        try:
            return json.loads(out.decode("utf-8"))
        except:
            return {"ok": False, "error": "Invalid output"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        temp.unlink(missing_ok=True)


# ================================================
# HTML REPORT
# ================================================

def build_html_report(data, html_path, png_path):
    html = f"""
<html>
<head>
<meta charset="utf-8">
<title>JS Анализ</title>
<style>
body {{ font-family: Arial; padding: 20px; }}
pre {{ background: #f0f0f0; padding: 10px; }}
</style>
</head>
<body>
<h1>Отчёт анализа JavaScript</h1>

<h2>Основные данные</h2>
<pre>{json.dumps({
    "file": data["file"],
    "size": data["size"]
}, indent=2, ensure_ascii=False)}</pre>

<h2>Граф вызовов функций</h2>
<img src="{png_path}" width="800"/>

<h2>Полный JSON-отчёт</h2>
<pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>

</body>
</html>
"""
    Path(html_path).write_text(html, encoding="utf-8")


# ================================================
# MAIN
# ================================================

def analyze_js(path):
    text = read_file(path)
    if not text:
        print("[!] Файл пуст")
        return

    init_v8_env()

    report = {
        "file": path,
        "size": len(text),
        "urls": detect_urls(text),
        "functions": detect_functions(text),
        "classes": detect_class_definitions(text),
        "suspicious": detect_suspicious(text),
        "exports": detect_exports(text),
        "imports": detect_require_import(text)[0],
        "requires": detect_require_import(text)[1],
        "base64": detect_base64(text),
        "hex": detect_hex_strings(text),
        "jsfuck_detected": detect_jsfuck(text),
        "obfuscator_io_detected": detect_obfuscator_io(text),
        "simple_deobfuscation_preview": simple_deobfuscate_vars(text)[:500],
        "call_graph": build_call_graph(text),
        "sandbox_example": run_js_sandbox("1+2")
    }

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_path = REPORT_DIR / f"report_{ts}.json"
    png_path = REPORT_DIR / f"callgraph_{ts}"
    html_path = REPORT_DIR / f"report_{ts}.html"

    # граф PNG
    render_call_graph_png(report["call_graph"], str(png_path))

    # html
    build_html_report(report, html_path, png_path + ".png")

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print(f"[OK] JSON:  {json_path}")
    print(f"[OK] PNG:   {png_path}.png")
    print(f"[OK] HTML:  {html_path}")


if __name__ == "__main__":
    analyze_js(JS_PATH)