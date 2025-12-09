#!/bin/bash

# Настройки
PARTS=("final_part1" "final_part2" "final_part3")
BIG_FILE="bigdump.txt"
REPORT_DIR="reports"
CHAT_REPORT="$REPORT_DIR/chat.txt"

# Список ключевых слов для поиска функций чата
KEYWORDS=("chat" "message" "send" "receive" "sticker" "mute" "pin" "admin" "delete" "clear" "ban" "kick" "setbalance" "mod" "owner" "reply")

# 1. Создаём или очищаем bigdump.txt
> "$BIG_FILE"

# 2. Объединяем все файлы из трёх папок
for DIR in "${PARTS[@]}"; do
    if [ -d "$DIR" ]; then
        find "$DIR" -type f -exec cat {} >> "$BIG_FILE" \;
    fi
done
echo "Все файлы объединены в $BIG_FILE"

# 3. Создаём папку для отчётов
mkdir -p "$REPORT_DIR"

# 4. Фильтруем по ключевым словам и создаём chat.txt
> "$CHAT_REPORT"
for WORD in "${KEYWORDS[@]}"; do
    grep -i "$WORD" "$BIG_FILE" >> "$CHAT_REPORT"
done
echo "Отчёт по функциям чата создан в $CHAT_REPORT"

# 5. Добавляем файлы в Git и пушим
git add "$BIG_FILE" "$CHAT_REPORT"
git commit -m "Созданы bigdump.txt и reports/chat.txt для анализа чата"
git push origin main

echo "Файлы bigdump.txt и reports/chat.txt добавлены в репозиторий и запушены"
