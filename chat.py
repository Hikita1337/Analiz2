import re
import os

INPUT_FILE = "bigdump.txt"
OUTPUT_API = "reports/api_ws.txt"
OUTPUT_FUNC = "reports/functions.txt"
SKIP_FILE  = "reports/skipped_lines.txt"
CONTEXT_LINES = 3
LOG_EVERY = 1

# Пропуск диапазонов строк
SKIP_LINES = set(range(41000, 42001))  # первый проблемный диапазон
SKIP_LINES.update(range(91240, 91301))  # второй проблемный диапазон

os.makedirs("reports", exist_ok=True)

# Регулярки
re_api = re.compile(r"(GET|POST|PUT|DELETE)\s+https?://[^\s\"']+")
re_fetch = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']")
re_ws_send = re.compile(r"ws\.send\s*\(\s*(.+?)\s*\)")
re_ws_recv = re.compile(r"onmessage\s*=\s*function\s*\(.*?\)")
re_function = re.compile(r"function\s+([A-Za-z0-9_]+)\s*\(")
re_arrow = re.compile(r"([A-Za-z0-9_]+)\s*=\s*\((.*?)\)\s*=>")

lines_buffer = []

with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f, \
     open(OUTPUT_API,"w",encoding="utf-8") as api_file, \
     open(OUTPUT_FUNC,"w",encoding="utf-8") as func_file, \
     open(SKIP_FILE,"w",encoding="utf-8") as skip_file:

    for line_number, line in enumerate(f, start=1):
        if line_number in SKIP_LINES:
            skip_file.write(f"Line {line_number} skipped.\n{line}\n{'-'*50}\n")
            continue

        try:
            lines_buffer.append(line.rstrip())
            if len(lines_buffer) > CONTEXT_LINES*2+1:
                lines_buffer.pop(0)

            context = "\n".join(lines_buffer)

            # API / fetch / WS
            if re_api.search(line) or re_fetch.search(line) or re_ws_send.search(line) or re_ws_recv.search(line):
                api_file.write(f"Line {line_number}:\n{context}\n{'='*80}\n")

            # Functions
            if re_function.search(line) or re_arrow.search(line):
                func_file.write(f"Line {line_number}:\n{context}\n")
                func_file.write("Usage/Interaction: Check above context for API/WebSocket calls\n")
                func_file.write("="*80 + "\n")

        except Exception as e:
            skip_file.write(f"Line {line_number} skipped. Exception: {e}\n{line}\n{'-'*50}\n")

        if line_number % LOG_EVERY == 0:
            print(f"Processed {line_number} lines")

print("DONE. API/WS saved in api_ws.txt, functions saved in functions.txt, skipped lines in skipped_lines.txt")