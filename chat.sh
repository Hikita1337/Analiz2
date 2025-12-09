#!/bin/bash
# find_chat_snippets.sh
# Полный автоматический анализ + push в репозиторий

set -euo pipefail

OUT_DIR="reports"
REPORT_FILE="${OUT_DIR}/chat.txt"
TMP_LIST="${OUT_DIR}/candidates.txt"

mkdir -p "${OUT_DIR}"

# Очищаем файлы
: > "${REPORT_FILE}"
: > "${TMP_LIST}"

# Ключевые слова
keywords=(
  "socket"
  "ws://"
  "wss://"
  "websocket"
  "send("
  "emit("
  "message"
  "\"type\":"
  "sticker"
  "sticker_id"
  "admin"
  "moderator"
  "command"
  "cmd"
  "/api/chat"
  "chat"
  "chat_id"
  "room"
  "channel"
  "token"
  "auth"
  "Authorization"
  "Bearer"
  "session"
  "history"
  "typing"
)

echo "=== CHAT ANALYSIS REPORT ===" >> "${REPORT_FILE}"
echo "Ключевые слова: ${keywords[*]}" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "Поиск файлов..."


tmp_matches=$(mktemp)

for kw in "${keywords[@]}"; do
  grep -RIn --binary-files=without-match \
    --exclude-dir=.git \
    --exclude-dir=node_modules \
    --exclude-dir=bin \
    --exclude-dir=images \
    --exclude-dir=img \
    -e "${kw}" . >> "${tmp_matches}" || true
done

# Уникальные файлы
awk -F: '{print $1}' "${tmp_matches}" | sort -u > "${TMP_LIST}"

echo "Найдено файлов-кандидатов: $(wc -l < "${TMP_LIST}")" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

# Добавляем контекст по каждому файлу
while IFS= read -r f; do
  echo "===== FILE: ${f} =====" >> "${REPORT_FILE}"
  grep -In --binary-files=without-match -n -E "$(IFS='|'; echo "${keywords[*]}")" "$f" | head -n 30 >> "${REPORT_FILE}" || true
  echo "" >> "${REPORT_FILE}"
done < "${TMP_LIST}"

# Статистика типов
echo "=== Статистика по типам файлов ===" >> "${REPORT_FILE}"
cut -d. -f2- "${TMP_LIST}" | sed -n 's/.*\.\([a-z0-9]\+\)$/\1/p' | sort | uniq -c | sort -nr >> "${REPORT_FILE}" || true

echo "Отчёт создан: ${REPORT_FILE}"

### АВТОМАТИЧЕСКИЙ PUSH В РЕПО
git add -f "${OUT_DIR}"
git commit -m "Automated chat analysis report"
git push origin HEAD

echo "Отчёт загружен в GitHub."