@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PYTHON_EXE=C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe"

if exist "%PYTHON_EXE%" (
  "%PYTHON_EXE%" "%SCRIPT_DIR%register_ui.py"
) else (
  python "%SCRIPT_DIR%register_ui.py"
)

endlocal
