#!/usr/bin/env bash
# MailScope launcher for macOS / Linux.   Usage:  bash start_mailscope.sh
# First run creates a private Python environment (.venv) and installs the requirements.
# Everything stays on this computer. Press Ctrl+C to stop.
set -u
cd "$(dirname "$0")" || exit 1

if [ ! -f app.py ]; then
  echo "This script is not next to app.py. Extract the whole zip first and run it from the extracted folder."
  exit 1
fi

PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    PY="$cand"; break
  fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ and run this again."
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "Creating a private Python environment (first run only)..."
  "$PY" -m venv .venv || { echo "Could not create the environment. Copy ALL the text above and include it when asking for help."; exit 1; }
fi

if [ ! -f .venv/mailscope_installed.txt ]; then
  echo "Installing what MailScope needs (first run only; needs internet; can take a few minutes)..."
  if .venv/bin/python -m pip install --upgrade pip >/dev/null 2>&1; .venv/bin/python -m pip install --prefer-binary -r requirements.txt; then
    echo installed > .venv/mailscope_installed.txt
  else
    echo "Installing failed. Copy ALL the text above and include it when asking for help."
    "$PY" -m mailscope.doctor
    exit 1
  fi
fi

echo
.venv/bin/python -m mailscope.doctor
echo
echo "Starting MailScope at http://127.0.0.1:8501  (open it in your browser if it does not open by itself)."
.venv/bin/python -c "import time, webbrowser; time.sleep(5); webbrowser.open('http://127.0.0.1:8501')" &
exec .venv/bin/python -m streamlit run app.py
