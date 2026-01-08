@echo off
cd /d "%~dp0"

echo ========================================
echo ARGUS - Browser Security Monitor
echo Phase 2.5 - Credential Theft Detection
echo ========================================
echo.

if not exist "x64\Debug\Argus.exe" (
    if not exist "x64\Release\Argus.exe" (
        echo Error: Argus.exe not found
        echo Please build the solution first in Visual Studio
        echo.
        echo Build steps:
        echo   1. Open Argus.sln in Visual Studio
        echo   2. Select x64 Debug or Release
        echo   3. Build ^> Build Solution
        pause
        exit /b 1
    )
    set BUILD_TYPE=Release
) else (
    set BUILD_TYPE=Debug
)

echo Running %BUILD_TYPE% build...
echo.

if not exist "logs" mkdir logs

"x64\%BUILD_TYPE%\Argus.exe"

echo.
echo ========================================
echo Session ended. Check logs\ directory for session log.
echo ========================================
pause
