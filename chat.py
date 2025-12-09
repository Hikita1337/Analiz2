#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ULTRA JS Analyzer — единый файл для Codespaces
Функции:
 - глубокий статический анализ
 - эвристическая "семантическая" генерация описаний функций на русском
 - оптимизированный граф вызовов (ограниченный по размеру)
 - попытки деобфускации таблиц _0x
 - безопасный sandbox (Node) для коротких тестов
 - JSON + HTML отчёты (на русском), PNG граф (если graphviz установлен)
 - опциональный автокоммит в git (--git-commit)
"""
import os
import sys
import re
import json
import subprocess
import base64
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Tuple

# ---------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------
JS_PATH_DEFAULT = "2025-12-09_09-42-51-297323.js"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
BASE64_LIMIT = 300
HEX_LIMIT = 300
GRAPH_FUNCS_LIMIT = 400           # сколько функций рендерить в PNG (чтобы не упасть)
DETAIL_FUNCS_LIMIT = 1200        # сколько функций детально описывать (ограничение)
SANDBOX_TIMEOUT = 2              # сек
AUTO_INSTALL_PY = True           # пытаться pip install недостающие python-пакеты
AUTO_INSTALL_SYS = True         # True попытается sudo apt install dot/node — отключено по умолчанию
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Auto-install python libs if missing
# ---------------------------------------------------------------------
def ensure_py_module(modname: str, pip_name: str = None):
    try:
        __import__(modname)
        return True
    except ImportError:
        if not AUTO_INSTALL_PY:
            print(f"[WARN] Модуль '{modname}' не установлен. Установи: pip install {pip_name or modname}")
            return False
        print(f"[INFO] Устанавливаю python-пакет: {pip_name or modname} ...")
        res = subprocess.run([sys.executable, "-m", "pip", "install", pip_name or modname])
        return res.returncode == 0

# required python packages
ensure_py_module("tqdm")
ensure_py_module("graphviz")  # optional — если fails, скрипт ещё работает, но PNG не будет

from tqdm import tqdm
try:
    from graphviz import Digraph
    GRAPHVIZ_AVAILABLE = True
except Exception:
    GRAPHVIZ_AVAILABLE = False

# ---------------------------------------------------------------------
# System binaries checks (dot, node)
# ---------------------------------------------------------------------
def has_binary(name: str) -> bool:
    return subprocess.call(f"which {name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

DOT_AVAILABLE = has_binary("dot") and GRAPHVIZ_AVAILABLE
NODE_AVAILABLE = has_binary("node")

if not DOT_AVAILABLE:
    print("[INFO] Graphviz (dot) недоступен или graphviz-python не установлен — PNG рендер отключен.")
if not NODE_AVAILABLE:
    print("[INFO] Node.js не найден — sandbox-тесты отключены.")

# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------
def read_file(path: str) -> str:
    try:
        txt = Path(path).read_text(errors="ignore")
        print(f"[*] Прочитан файл {path} ({len(txt)} байт)")
        return txt
    except Exception as e:
        print(f"[ERROR] Не удалось прочитать {path}: {e}")
        return ""

def safe_write(path: Path, data: str, encoding="utf-8"):
    path.write_text(data, encoding=encoding)
    print(f"[*] Сохранено: {path}")

def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# ---------------------------------------------------------------------
# DETECTORS: URLs, Base64, HEX, imports/exports, suspicious tokens
# ---------------------------------------------------------------------
def detect_urls(text: str) -> List[str]:
    return sorted(set(re.findall(r'https?://[^\s\'"\)\]]+', text)))

def detect_base64(text: str, limit=BASE64_LIMIT) -> List[Tuple[str,str]]:
    regex = r'(?:[A-Za-z0-9+/]{20,}={0,2})'
    found = re.findall(regex, text)[:limit]
    out = {}
    for chunk in tqdm(found, desc="Base64 декодирование", leave=False):
        try:
            dec = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if dec.strip():
                out[chunk] = dec
        except Exception:
            continue
    return list(out.items())

def detect_hex(text: str, limit=HEX_LIMIT) -> List[Tuple[str,str]]:
    regex = r'(?:[0-9a-fA-F]{2}){8,}'
    found = re.findall(regex, text)[:limit]
    out = {}
    for h in tqdm(found, desc="HEX декодирование", leave=False):
        try:
            dec = bytes.fromhex(h).decode("utf-8", errors="ignore")
            if dec.strip():
                out[h] = dec
        except Exception:
            continue
    return list(out.items())

def detect_imports_exports(text: str) -> Tuple[List[str], List[str]]:
    imports = sorted(set(re.findall(r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]', text)))
    requires = sorted(set(re.findall(r'require\([\'"]([^\'"]+)[\'"]\)', text)))
    exports = sorted(set(re.findall(r'export\s+(?:default\s+)?(\w+)', text)))
    return imports + requires, exports

def detect_suspicious(text: str) -> List[str]:
    suspects = ["eval(", "new Function", "Function(", "atob(", "btoa(", "crypto", "fetch(", "XMLHttpRequest", "$.ajax", "WebSocket", "while(true)", "setInterval("]
    return [s for s in suspects if s in text]

# ---------------------------------------------------------------------
# FUNCTIONS EXTRACTION (более продвинутый парсер на основе regex-эвристик)
# ---------------------------------------------------------------------
FUNC_DEF_REGEX = re.compile(r'''
    (?:function\s+([A-Za-z_]\w*)\s*\(([^\)]*)\))     # function name(args)
    |(?:([A-Za-z_]\w*)\s*=\s*function\s*\(([^\)]*)\)) # name = function(args)
    |(?:([A-Za-z_]\w*)\s*=\s*\(?([^\)]*)\)?\s*=>)     # name = (...) =>
''', re.VERBOSE)

def extract_functions(text: str) -> List[Dict]:
    funcs = {}
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        m = FUNC_DEF_REGEX.search(line)
        if m:
            name = m.group(1) or m.group(3) or m.group(5)
            raw_params = m.group(2) or m.group(4) or m.group(6) or ""
            params = [p.strip() for p in raw_params.split(",") if p.strip()]
            if name and name not in funcs:
                # get preview: current line + next 20 lines
                preview = line.strip()
                preview_body = "\n".join(lines[idx:idx+25])
                funcs[name] = {"name": name, "params": params, "preview": preview_body, "defline": preview}
    return list(funcs.values())

# ---------------------------------------------------------------------
# CALL COUNTS (быстрый одноразовый проход)
# ---------------------------------------------------------------------
CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
def count_calls(text: str) -> Counter:
    names = CALL_RE.findall(text)
    return Counter(names)

# ---------------------------------------------------------------------
# BEHAVIOR ENGINE: категории, рекомендации, примеры вызовов
# ---------------------------------------------------------------------
def categorize_preview(preview: str) -> List[str]:
    p = preview.lower()
    cats = []
    if 'fetch(' in p or 'xmlhttprequest' in p or '$.ajax' in p or 'axios' in p:
        cats.append("сеть")
    if 'websocket' in p or 'ws.' in p:
        cats.append("websocket")
    if 'eval(' in p or 'new Function' in p or 'Function(' in p:
        cats.append("динамический код")
    if 'btoa' in p or 'atob' in p or 'crypto' in p or 'subtle' in p:
        cats.append("крипто/кодирование")
    if 'document.' in p or 'getelementbyid' in p or 'queryselector' in p:
        cats.append("DOM")
    if 'settimeout' in p or 'setinterval' in p or 'async' in p or 'await' in p or 'promise' in p:
        cats.append("асинхронность")
    if not cats:
        cats.append("утилитарная/логическая")
    return cats

def generate_example_call(name: str, params: List[str], categories: List[str]) -> str:
    args = []
    for p in params:
        pn = p.lower()
        if 'url' in pn:
            args.append("'https://example.com/api'")
        elif 'token' in pn or 'auth' in pn:
            args.append("'<ваш_токен>'")
        elif 'data' in pn or 'body' in pn or 'payload' in pn:
            args.append('{"key":"value"}')
        elif 'cb' in pn or 'callback' in pn:
            args.append("() => { /* callback */ }")
        else:
            args.append("'пример'")
    if not args and 'сеть' in categories:
        return "fetch('https://example.com').then(r=>r.json());"
    return f"{name}({', '.join(args)});"

def describe_function_entry(entry: Dict, call_count: int) -> Dict:
    name = entry["name"]
    params = entry.get("params", [])
    preview = entry.get("preview", "")
    cats = categorize_preview(preview)
    example = generate_example_call(name, params, cats)
    desc_lines = []
    desc_lines.append(f"Функция: {name}")
    desc_lines.append(f"Определена: {entry.get('defline')}")
    desc_lines.append(f"Параметры: {len(params)} ({', '.join(params) if params else 'нет явно'})")
    desc_lines.append(f"Категории: {', '.join(cats)}")
    desc_lines.append(f"Число упоминаний (вызовов) в файле (оценка): {call_count}")
    desc_lines.append("Пример вызова:")
    desc_lines.append(f"  {example}")
    recs = []
    if 'сеть' in cats:
        recs.append("Использует сетевые запросы — при тестировании подменять/мокать ответы.")
    if 'динамический код' in cats:
        recs.append("Содержит eval/Function — потенциально выполняет динамический/обфусцированный код; запускать осторожно.")
    if 'крипто/кодирование' in cats:
        recs.append("Работает с кодированием/крипто — возможно обрабатывает токены/ключи.")
    if 'DOM' in cats:
        recs.append("Взаимодействует с DOM — в Node часть вызовов не будет работать без mocking.")
    if recs:
        desc_lines.append("Рекомендации: " + " ".join(recs))
    return {
        "name": name,
        "params": params,
        "call_count": call_count,
        "categories": cats,
        "example": example,
        "description_text": "\n".join(desc_lines)
    }

# ---------------------------------------------------------------------
# DEOBFUSCATION (примитивная попытка: таблицы вида _0x... = [...])
# ---------------------------------------------------------------------
def attempt_deobfuscate_table(text: str, max_table_len=5000) -> Dict[str,str]:
    """
    Ищет простые таблицы строк, типа:
      var _0xabc = ['a','b','c']; function _0x12(i){ return _0xabc[i]; }
    Возвращает словарь mapping index->string если найдено.
    Это очень эвристично — работает на простых случаях Obfuscator.io.
    """
    res = {}
    # pattern for array of strings assignment: var _0xabc = ['str1','str2',...];
    arrs = re.findall(r'var\s+(_0x[a-f0-9]+)\s*=\s*\[([^\]]{0,4000})\]', text)
    for name, inside in arrs:
        # split naive by commas of quoted strings
        strs = re.findall(r'["\']([^"\']+)["\']', inside)
        if strs:
            for i, s in enumerate(strs):
                res[f"{name}[{i}]"] = s
            # also store mapping name:i -> s
            for i,s in enumerate(strs):
                res[f"{name}:{i}"] = s
    return res

# ---------------------------------------------------------------------
# BUILD OPTIMIZED CALL GRAPH (только для top-N функций)
# ---------------------------------------------------------------------
def build_optimized_graph(text: str, functions: List[Dict], calls_counter: Counter, limit=GRAPH_FUNCS_LIMIT):
    names = [f["name"] for f in functions]
    # sort names by call_count desc
    ranked = sorted(names, key=lambda n: (-calls_counter.get(n,0), n))
    selected = ranked[:limit]
    graph = {n: set() for n in selected}
    # find windows around function definitions to search calls
    # prepare pattern to find "function name" occurrences
    pattern = re.compile(r'function\s+({})\s*\('.format("|".join(re.escape(n) for n in selected)))
    for m in pattern.finditer(text):
        name = m.group(1)
        start = max(0, m.start() - 200)
        end = min(len(text), m.end() + 3000)
        window = text[start:end]
        # find calls inside window
        for callee in CALL_RE.findall(window):
            if callee in graph and callee != name:
                graph[name].add(callee)
    # convert sets to sorted lists
    return {k: sorted(list(v)) for k, v in graph.items()}

# ---------------------------------------------------------------------
# RENDER GRAPHVIZ PNG
# ---------------------------------------------------------------------
def render_graph_png(graph: Dict[str,List[str]], out_base: Path) -> Path:
    if not GRAPHVIZ_AVAILABLE or not DOT_AVAILABLE:
        return None
    dot = Digraph("callgraph", format="png")
    dot.attr(rankdir="LR")
    # limit nodes drawn to those present (already limited upstream)
    for n in graph:
        dot.node(n)
    for a, bs in graph.items():
        for b in bs:
            dot.edge(a, b)
    out = str(out_base)
    dot.render(out, cleanup=True)
    return Path(out + ".png")

# ---------------------------------------------------------------------
# SANDBOX (выполнение безопасных фрагментов в Node)
# ---------------------------------------------------------------------
def run_node_snippet(js_code: str, timeout: int = SANDBOX_TIMEOUT) -> str:
    if not NODE_AVAILABLE:
        return "Node не доступен"
    # run node -e "..." safely; limit time
    try:
        proc = subprocess.run(["node", "-e", js_code], capture_output=True, text=True, timeout=timeout)
        out = proc.stdout.strip()
        err = proc.stderr.strip()
        if err:
            return f"stderr: {err}"
        return out or "Нет вывода"
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return f"Ошибка sandbox: {e}"

# ---------------------------------------------------------------------
# AUTO-COMMIT optionally
# ---------------------------------------------------------------------
def git_commit_reports(report_files: List[Path], message: str = None) -> Tuple[bool,str]:
    try:
        # ensure git available
        if subprocess.call("git --version", shell=True, stdout=subprocess.DEVNULL) != 0:
            return False, "git не найден"
        # add files
        for p in report_files:
            subprocess.run(["git", "add", str(p)])
        msg = message or f"Auto report {timestamp()}"
        subprocess.run(["git", "commit", "-m", msg])
        # push (can fail if no upstream)
        res = subprocess.run(["git", "push"], capture_output=True, text=True)
        if res.returncode != 0:
            return True, "committed locally, push failed or not configured: " + res.stderr.strip()
        return True, "committed and pushed"
    except Exception as e:
        return False, str(e)

# ---------------------------------------------------------------------
# MAIN ANALYSIS PIPELINE
# ---------------------------------------------------------------------
def ultra_analyze(js_path: str, auto_git: bool = False):
    text = read_file(js_path)
    if not text:
        print("[ERROR] Файл пуст или не найден.")
        return

    # stage 1: quick detectors
    print("[1/8] Поиск URL, base64, hex, импорты/экспорты, подозрительное...")
    urls = detect_urls(text)
    b64 = detect_base64(text)
    hexs = detect_hex(text)
    imports, exports = detect_imports_exports(text)
    suspicious = detect_suspicious(text)
    jsfuck = detect_jsfuck(text)
    deobf_map = attempt_deobfuscate_table(text)
    obfuscator_sig = detect_obfuscator(text)

    # stage 2: functions extraction
    print("[2/8] Извлечение определений функций (эвристика)...")
    funcs = extract_functions(text)
    print(f"    найдено функций (синтаксически): {len(funcs)}")

    # stage 3: calls counting
    print("[3/8] Подсчёт упоминаний/вызовов (быстрый проход)...")
    calls_counter = count_calls(text)
    # attach counts
    for f in funcs:
        f["call_count"] = calls_counter.get(f["name"], 0)

    # stage 4: rank and describe
    print("[4/8] Генерация описаний функций (эвристика, на русском)...")
    funcs_sorted = sorted(funcs, key=lambda x: (-x.get("call_count",0), x["name"]))
    detail_limit = min(DETAIL_FUNCS_LIMIT, len(funcs_sorted))
    functions_report = []
    for f in tqdm(funcs_sorted[:detail_limit], desc="Описание функций"):
        entry = describe_function_entry(f, f.get("call_count",0))
        functions_report.append(entry)

    # stage 5: build optimized call graph
    print("[5/8] Построение оптимизированного графа вызовов (ограничено)...")
    optimized_graph = build_optimized_graph(text, funcs_sorted, calls_counter, limit=GRAPH_FUNCS_LIMIT)

    # stage 6: attempt decode obf strings (preview)
    print("[6/8] Попытка примитивной деобфускации таблиц...")
    deobf_preview = {k:v for k,v in list(deobf_map.items())[:200]}

    # stage 7: sandbox test (short)
    print("[7/8] Тест sandbox (короткий) ...")
    sandbox_result = run_node_snippet("console.log('sandbox OK')") if NODE_AVAILABLE else "Node недоступен"

    # assemble report
    print("[8/8] Формирование отчётов (JSON + HTML + PNG если возможно)...")
    report = {
        "meta": {
            "file": js_path,
            "size_bytes": len(text),
            "generated": timestamp()
        },
        "urls": urls,
        "base64_preview": [{"orig": o, "decoded_preview": (d[:200] + '...') if len(d)>200 else d} for o,d in b64],
        "hex_preview": [{"orig": o, "decoded_preview": (d[:200] + '...') if len(d)>200 else d} for o,d in hexs],
        "imports_exports": {"imports": imports, "exports": exports},
        "suspicious_tokens": suspicious,
        "jsfuck_detected": bool(jsfuck),
        "obfuscator_signature": bool(obfuscator_sig),
        "deobfuscation_preview": deobf_preview,
        "functions_count": len(funcs),
        "functions_top": [{"name":f["name"], "call_count": f.get("call_count",0)} for f in funcs_sorted[:200]],
        "functions_detailed": functions_report,
        "optimized_call_graph": optimized_graph,
        "sandbox_test": sandbox_result
    }

    ts = timestamp()
    json_path = REPORT_DIR / f"ultra_report_{ts}.json"
    safe_write(json_path, json.dumps(report, indent=2, ensure_ascii=False))

    # attempt render png
    png_path = None
    if optimized_graph and GRAPHVIZ_AVAILABLE and DOT_AVAILABLE:
        try:
            out_base = REPORT_DIR / f"callgraph_{ts}"
            png_path = render_graph_png(optimized_graph, out_base)
            if png_path:
                print(f"[*] PNG граф сохранён: {png_path}")
        except Exception as e:
            print(f"[WARN] Ошибка Graphviz: {e}")

    # build HTML (русский)
    html_path = REPORT_DIR / f"ultra_report_{ts}.html"
    html_sections = []
    html_sections.append(f"<h1>ULTRA Отчёт анализа: {Path(js_path).name}</h1>")
    html_sections.append(f"<p>Размер файла: {len(text)} байт — <i>сформирован: {ts}</i></p>")
    html_sections.append("<h2>Краткая информация</h2>")
    html_sections.append(f"<p>Найдено уникальных URL: {len(urls)}; подозрительных токенов: {len(suspicious)}; функций (синтаксически): {len(funcs)}</p>")
    html_sections.append("<h2>Уникальные URL</h2><pre>{}</pre>".format(json.dumps(urls, ensure_ascii=False, indent=2)))
    html_sections.append("<h2>Подозрительные конструкции</h2><pre>{}</pre>".format(json.dumps(suspicious, ensure_ascii=False, indent=2)))
    if png_path:
        html_sections.append("<h2>Граф вызовов (PNG, топ функций)</h2>")
        html_sections.append(f"<img src=\"{Path(png_path).name}\" style=\"max-width:100%;height:auto;\"/>")
    else:
        html_sections.append("<h2>Граф вызовов (JSON)</h2>")
        html_sections.append("<pre>{}</pre>".format(json.dumps(optimized_graph, ensure_ascii=False, indent=2)))
    # include some function descriptions (first N)
    HTML_LIMIT = 200
    html_sections.append(f"<h2>Подробные описания функций (первые {min(HTML_LIMIT,len(functions_report))})</h2>")
    for f in functions_report[:HTML_LIMIT]:
        html_sections.append(f"<h3>{f['name']} — вызовов: {f['call_count']}</h3>")
        html_sections.append(f"<pre>{f['description_text']}</pre>")
        html_sections.append(f"<pre>Пример: {f['example']}</pre>")
    html_sections.append("<h2>Sandbox тест</h2><pre>{}</pre>".format(sandbox_result))
    html_content = "<html><head><meta charset='utf-8'><title>ULTRA Отчёт</title></head><body>{}</body></html>".format("\n".join(html_sections))
    safe_write(html_path, html_content)

    print("[*] Отчёты созданы в папке reports/")

    # optional git commit
    if auto_git:
        print("[*] Пытаемся сделать git commit отчётов...")
        ok, msg = git_commit_reports([json_path, html_path] + ([png_path] if png_path else []))
        if ok:
            print("[*] Git commit: OK —", msg)
        else:
            print("[WARN] Git commit failed —", msg)

    print("[*] ULTRA анализ завершён.")

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def usage():
    print("Usage: python3 ultra_analyzer.py <path/to/file.js> [--git-commit]")
    print("Если путь не указан, будет использован:", JS_PATH_DEFAULT)

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        path = JS_PATH_DEFAULT
        auto_git = False
    else:
        path = args[0]
        auto_git = "--git-commit" in args
    if not Path(path).exists():
        print(f"[ERROR] Файл не найден: {path}")
        usage()
        sys.exit(1)
    ultra_analyze(path, auto_git=auto_git)