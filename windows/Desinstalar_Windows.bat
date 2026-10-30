@echo off
title Desinstalador - Custodio Credenciales
cd /d "%~dp0"

echo ========================================================
echo   DESINSTALADOR DE CUSTODIO CREDENCIALES
echo ========================================================
echo.
echo Esto eliminara el acceso directo y la aplicacion del sistema.
echo (Tus datos en el navegador se mantendran seguros en IndexedDB).
echo.
pause

set "INSTALL_DIR=%LOCALAPPDATA%\CustodioCredenciales"
rmdir /S /Q "%INSTALL_DIR%" 2>nul
del "%USERPROFILE%\Desktop\Custodio Credenciales.lnk" 2>nul

echo.
echo [OK] Desinstalacion completada con exito.
pause
