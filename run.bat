@echo off
REM Activate virtualenv if present, otherwise use system python
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)
python -m pip install -r requirements.txt
python bot.py
pause