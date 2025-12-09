#!/bin/bash
set -e

# --- Установка pyenv ---
if ! command -v pyenv >/dev/null 2>&1; then
  echo "Installing pyenv..."
  curl https://pyenv.run | bash
fi

# --- Настройка окружения pyenv ---
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# --- Установка Python 3.11.8 ---
PYTHON_VERSION="3.11.8"
if ! pyenv versions | grep -q "$PYTHON_VERSION"; then
  echo "Installing Python $PYTHON_VERSION..."
  pyenv install $PYTHON_VERSION
fi

# --- Используем эту версию локально в репозитории ---
pyenv local $PYTHON_VERSION
echo "Python version set to $(python --version)"

# --- Установка RE2 ---
pip install --upgrade pip
pip install re2

echo "Setup complete. You can now run your scripts with Python 3.11 and RE2."