#!/usr/bin/env bash
set -e
# Activate virtualenv if present, otherwise use system python
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi
python3 -m pip install -r requirements.txt
python3 bot.py