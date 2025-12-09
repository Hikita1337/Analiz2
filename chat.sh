#!/bin/bash

PARTS=("final_part1" "final_part2" "final_part3")
BIG_FILE="bigdump.txt"
TMP_FILE="tmp_combined.txt"

# 1. Объединяем все файлы из папок в один временный файл
> "$TMP_FILE"
for DIR in "${PARTS[@]}"; do
    if [ -d "$DIR" ]; then
        find "$DIR" -type f -exec cat {} + >> "$TMP_FILE"
    fi
done

# 2. Сравниваем с bigdump.txt
if cmp -s "$TMP_FILE" "$BIG_FILE"; then
    echo "✅ Все строки из папок точно совпадают с bigdump.txt"
else
    echo "⚠️ Найдены различия между папками и bigdump.txt"

    # Выводим первые 20 различий для анализа
    echo "Первые 20 различий:"
    diff -u "$TMP_FILE" "$BIG_FILE" | head -n 40
fi

# 3. Убираем временный файл
rm "$TMP_FILE"