#!/bin/bash
set -e

PYTHON_VERSION="3.11.8"
VENV_DIR=".venv_py311"

# --- Проверяем, установлен ли pyenv ---
if ! command -v pyenv >/dev/null 2>&1; then
  echo "Installing pyenv..."
  curl https://pyenv.run | bash
fi

# --- Настройка окружения pyenv ---
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# --- Установка Python 3.11.8 через pyenv ---
if ! pyenv versions | grep -q "$PYTHON_VERSION"; then
  echo "Installing Python $PYTHON_VERSION..."
  pyenv install $PYTHON_VERSION
fi

# --- Создание виртуального окружения ---
PYTHON_BIN=$(pyenv prefix $PYTHON_VERSION)/bin/python3
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment in $VENV_DIR..."
  $PYTHON_BIN -m venv $VENV_DIR
fi

# --- Активация виртуального окружения ---
source $VENV_DIR/bin/activate

# --- Обновление pip и установка RE2 ---
pip install --upgrade pip
pip install re2

# --- Проверка версии Python и RE2 ---
echo "Python version: $(python --version)"
python -c "import re2; print('re2 installed successfully')"

echo "Setup complete. To activate, run: source $VENV_DIR/bin/activate"