#!/bin/bash
# ==============================================================================
# INSTALADOR AUTOMÁTICO PARA macOS
# ==============================================================================

DIR="$(cd "$(dirname "$0")" && pwd)"
APP_SRC="$DIR/Custodio Credenciales.app"

echo "========================================================"
echo "   🛡️ INSTALADOR DE CUSTODIO CREDENCIALES (macOS) 🛡️"
echo "========================================================"
echo ""
echo "Instalando la aplicación en tu Mac..."

TARGET_DIR="/Applications"
if [ ! -w "/Applications" ]; then
    TARGET_DIR="$HOME/Applications"
    mkdir -p "$TARGET_DIR"
fi

# Copiar app
cp -R "$APP_SRC" "$TARGET_DIR/"

# Crear acceso directo en el Escritorio
ln -sf "$TARGET_DIR/Custodio Credenciales.app" "$HOME/Desktop/Custodio Credenciales"

echo ""
echo "✅ ¡INSTALACIÓN COMPLETADA CON ÉXITO!"
echo ""
echo "Se ha creado la aplicación en: $TARGET_DIR/Custodio Credenciales.app"
echo "Y un acceso directo en tu Escritorio: ~/Desktop/Custodio Credenciales"
echo ""
echo "Ya puedes abrirla desde tu Launchpad, desde Aplicaciones o desde tu Escritorio."
echo ""
read -p "Presiona ENTER para abrir la aplicación ahora..."
open "$TARGET_DIR/Custodio Credenciales.app"
