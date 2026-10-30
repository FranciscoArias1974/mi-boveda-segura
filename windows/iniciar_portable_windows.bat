@echo off
title Custodio Credenciales (Modo Portable)
cd /d "%~dp0\app"
start "" wscript.exe "%~dp0app\launcher.vbs"
