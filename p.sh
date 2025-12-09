#!/bin/bash

SRC_DIR="final"

# Считаем количество файлов
TOTAL_FILES=$(find "$SRC_DIR" -type f | wc -l)
echo "Всего файлов в $SRC_DIR: $TOTAL_FILES"

# Вычисляем количество папок, чтобы максимум 1000 файлов в каждой
MAX_PER_DIR=1000
NUM_DIRS=$(( (TOTAL_FILES + MAX_PER_DIR - 1) / MAX_PER_DIR ))
echo "Разделим на $NUM_DIRS папок по максимум $MAX_PER_DIR файлов"

# Создаём папки
for ((i=1; i<=NUM_DIRS; i++)); do
    mkdir -p "${SRC_DIR}_part$i"
done

# Распределяем файлы
i=0
for file in "$SRC_DIR"/*; do
    DIR_NUM=$(( i / MAX_PER_DIR + 1 ))
    mv "$file" "${SRC_DIR}_part${DIR_NUM}/"
    i=$((i+1))
done

echo "Готово! Файлы разбиты на папки: ${SRC_DIR}_part1 … ${SRC_DIR}_part${NUM_DIRS}"
