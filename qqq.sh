#!/bin/bash

# Настройки
EXTRACTED_DIR="extracted"
FINAL_DIR="final"
FILE_ID="1UlFwdxNXRAEcgy8Fh5bzh8PgxikO9C6t"
ZIP_FILE="temp.zip"
COMMIT_MSG="Добавлены файлы из zip"

# Установка gdown, если нет
if ! command -v gdown &> /dev/null; then
    pip install gdown --quiet
fi

# Скачиваем файл
echo "Скачиваем zip..."
gdown "https://drive.google.com/uc?id=${FILE_ID}" -O "${ZIP_FILE}"

# Создаём папки
mkdir -p "${EXTRACTED_DIR}" "${FINAL_DIR}"

# Распаковываем
echo "Распаковываем zip..."
unzip -q "${ZIP_FILE}" -d "${EXTRACTED_DIR}"

# Фильтруем файлы и перемещаем в финальную папку
echo "Собираем файлы..."
find "${EXTRACTED_DIR}" -type f ! -name "*.png" ! -name "*.webp" ! -name "*.bin" -exec mv {} "${FINAL_DIR}/" \;

# Чистим временный zip
rm "${ZIP_FILE}"

# Добавляем в Git и пушим
echo "Добавляем файлы в Git..."
git add -f "${FINAL_DIR}"
git commit -m "${COMMIT_MSG}"
git push origin main

echo "Готово! Все файлы в папке ${FINAL_DIR} добавлены в репозиторий."