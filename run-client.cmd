@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m client
    goto done
)
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m client
    goto done
)
where python >nul 2>nul
if not errorlevel 1 (
    python -m client
    goto done
)
echo Install Python 3.12+ from python.org with Tcl/Tk and Add Python to PATH.
:done
if errorlevel 1 (
    echo.
    echo Cannot start client. Read docs\DEMO.md. No pip packages are required.
    pause
)
