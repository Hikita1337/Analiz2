#!/bin/bash

# Папки, которые нужно проверить
PARTS=("final_part1" "final_part2" "final_part3")

TOTAL_SIZE=0

echo "Проверка размеров папок..."

for DIR in "${PARTS[@]}"; do
    if [ -d "$DIR" ]; then
        SIZE=$(du -sb "$DIR" | awk '{print $1}')
        echo "Размер папки $DIR: $SIZE байт"
        TOTAL_SIZE=$((TOTAL_SIZE + SIZE))
    else
        echo "Папка $DIR не найдена"
    fi
done

echo "-----------------------------------"
echo "Общий размер всех папок: $TOTAL_SIZE байт"

# Для более читаемого формата (КБ, МБ, ГБ)
echo "Общий размер (читаемый формат):"
du -ch "${PARTS[@]}" | grep total$