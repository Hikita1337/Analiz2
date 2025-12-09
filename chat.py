import re
import json
import os
from collections import defaultdict

BIG_FILE = "bigdump.txt"
REPORT_DIR = "reports"
OUTPUT_FILE = os.path.join(REPORT_DIR, "chat_full_analysis.json")

KEYWORDS = {
    "chat": ["chat", "message", "send", "receive", "sticker"],
    "admin": ["admin", "mute", "pin", "delete", "clear", "ban", "kick", "setbalance"]
}

# Создаём папку для отчётов
os.makedirs(REPORT_DIR, exist_ok=True)

# Словарь для хранения функций и блоков кода
functions = defaultdict(list)
graph = defaultdict(list)

# Читаем bigdump.txt
with open(BIG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

# Проходим построчно и выделяем блоки вокруг ключевых слов
context_size = 15  # сколько строк до и после
for i, line in enumerate(lines):
    for category, words in KEYWORDS.items():
        for word in words:
            if re.search(rf"\b{word}\b", line, re.IGNORECASE):
                start = max(0, i - context_size)
                end = min(len(lines), i + context_size + 1)
                block = "".join(lines[start:end])
                functions[category].append(block)
                # Простейший граф: категория -> слово
                graph[category].append(word)

# Убираем дубликаты блоков
for k in functions:
    functions[k] = list(set(functions[k]))
    graph[k] = list(set(graph[k]))

# Формируем JSON структуру
result = {
    "functions": functions,
    "graph": graph
}

# Сохраняем в JSON
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=4)

# Git push (если репозиторий и git уже инициализирован)
os.system(f"git add {OUTPUT_FILE}")
os.system(f'git commit -m "Добавлен структурированный анализ чата с классификацией и графом"')
os.system("git push origin main")

print(f"Готово! Отчёт сохранён: {OUTPUT_FILE}")