@echo off
echo ========================================
echo ARGUS - Browser Security Monitor
echo Phase 1 - Local Read-Only Observation
echo ========================================
echo.

if not exist "x64\Debug\Argus.exe" (
    if not exist "x64\Release\Argus.exe" (
        echo Error: Argus.exe not found
        echo Please build the solution first
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

x64\%BUILD_TYPE%\Argus.exe

echo.
echo ========================================
echo Session ended. Check logs\ directory for session log.
echo ========================================
pause
