@echo off
:: ==============================================================================
:: INSTALADOR AUTOMÁTICO PARA WINDOWS
:: ==============================================================================

title Instalador - Custodio Local de Credenciales
cd /d "%~dp0"

echo ========================================================
echo    🛡️ INSTALADOR DE CUSTODIO CREDENCIALES (WINDOWS) 🛡️
echo ========================================================
echo.
echo Instalando la aplicacion en tu computadora...
echo.

set "INSTALL_DIR=%LOCALAPPDATA%\CustodioCredenciales"
mkdir "%INSTALL_DIR%" 2>nul

:: Copiar archivos del programa
xcopy /E /I /Y "app\*" "%INSTALL_DIR%\" >nul

:: Crear acceso directo en el Escritorio usando PowerShell
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([System.IO.Path]::Combine([System.Environment]::GetFolderPath('Desktop'), 'Custodio Credenciales.lnk')); $s.TargetPath = 'wscript.exe'; $s.Arguments = '\"' + [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA') + '\CustodioCredenciales\launcher.vbs\"'; $s.WorkingDirectory = [System.Environment]::GetEnvironmentVariable('LOCALAPPDATA') + '\CustodioCredenciales'; $s.Description = 'Custodio Local de Credenciales (Boveda Segura)'; $s.Save()"

echo.
echo ========================================================
echo    [OK] ¡INSTALACION COMPLETADA EXITOSAMENTE!
echo ========================================================
echo.
echo 1. Se ha instalado en: %INSTALL_DIR%
echo 2. Se ha creado un acceso directo en tu Escritorio:
echo    "Custodio Credenciales"
echo.
echo Ya puedes cerrar esta ventana y abrir el acceso directo de tu Escritorio.
echo.
pause

:: Abrir de inmediato la aplicacion instalada
start "" wscript.exe "%INSTALL_DIR%\launcher.vbs"
