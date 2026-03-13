@echo off
REM PDF QES Signer - Windows Setup Script
REM Run this script once to create the virtual environment and install dependencies.

setlocal enabledelayedexpansion

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
echo [OK] Python found: %PYVER%

REM Create virtual environment
if exist .venv (
    echo [!]  Virtual environment already exists, skipping creation.
) else (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
)

REM Activate venv
call .venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip --quiet
echo [OK] pip upgraded.

echo.
echo Installing packages:

REM Required packages - abort if any fails
for %%P in (pymupdf Pillow PyQt6 cryptography pyhanko pyhanko-certvalidator) do (
    echo   ^* %%P ...
    pip install %%P
    if errorlevel 1 (
        echo.
        echo ERROR: Could not install required package %%P.
        echo        Please check your internet connection and try again.
        pause
        exit /b 1
    )
    echo [OK] %%P installed.
    echo.
)

REM Verify pymupdf actually imports (DLL check - requires VC++ Redistributable)
echo   ^* Verifying pymupdf import ...
python -c "import pymupdf" >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: PyMuPDF was installed but cannot be imported.
    echo        This usually means the Microsoft Visual C++ Redistributable is missing.
    echo.
    echo        Please download and install it, then re-run this setup:
    echo        https://aka.ms/vs/17/release/vc_redist.x64.exe
    echo.
    pause
    exit /b 1
)
echo [OK] pymupdf import verified.
echo.

REM python-pkcs11 is optional on Windows (may require a C compiler / CFFI)
echo   ^* python-pkcs11 (optional) ...
pip install python-pkcs11
if errorlevel 1 (
    echo [!]  python-pkcs11 could not be installed - PKCS#11 token support unavailable.
    echo      To enable it later, install Visual Studio Build Tools and run:
    echo        .venv\Scripts\pip install python-pkcs11
) else (
    echo [OK] python-pkcs11 installed.
)
echo.

REM Install the package itself so importlib.metadata finds the version
echo   ^* pdf-qes-signer (package metadata) ...
pip install -e . --quiet
if errorlevel 1 (
    echo [!]  Package self-install failed - version will show as 0.0.0+dev.
) else (
    echo [OK] Package installed.
)

REM Create launcher
echo.
echo Creating start_signer.bat...
(
    echo @echo off
    echo call "%%~dp0.venv\Scripts\activate.bat"
    echo python -m pdf_signer %%*
) > start_signer.bat
echo [OK] Launcher created: start_signer.bat

echo.
echo ============================================================
echo  Setup complete!
echo  Start the application with:  start_signer.bat
echo ============================================================
echo.
pause
