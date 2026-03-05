@echo off
REM PDF QES Signer - Windows Setup Script
REM Run this script once to create the virtual environment and install dependencies.

setlocal

echo.
echo ============================================================
echo  PDF QES Signer - Setup
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.9 or later from
    echo        https://www.python.org/downloads/
    echo        Make sure to check "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version') do set PYVER=%%v
echo Python found: %PYVER%

REM Create virtual environment
if exist .venv (
    echo Virtual environment already exists, skipping creation.
) else (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

REM Activate and install dependencies
echo Installing dependencies...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
pip install pymupdf pyhanko pyhanko-certvalidator python-pkcs11 Pillow PyQt6 cryptography

if errorlevel 1 (
    echo.
    echo ERROR: Dependency installation failed.
    pause
    exit /b 1
)

REM Create launcher
echo Creating start_signer.bat...
(
    echo @echo off
    echo call "%~dp0.venv\Scripts\activate.bat"
    echo python -m pdf_signer %%*
) > start_signer.bat

echo.
echo ============================================================
echo  Setup complete!
echo  Start the application with:  start_signer.bat
echo ============================================================
echo.
pause
