# 🛡️ Custodio Local de Credenciales (Secure Vault)

[![Licencia](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)
[![Seguridad](https://img.shields.io/badge/criptografía-AES--GCM%20256%20%7C%20PBKDF2-green.svg)](#-arquitectura-criptográfica-y-de-seguridad)
[![Plataformas](https://img.shields.io/badge/plataformas-macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS-orange.svg)](#-instalación-por-plataforma)
[![Biometría](https://img.shields.io/badge/biometría-Touch%20ID%20%7C%20Windows%20Hello%20%7C%20Face%20ID-blueviolet.svg)](#-soporte-biométrico-nativo)

Aplicación multiplataforma completa, local y soberana para la gestión, custodia y auditoría de credenciales externas, diseñada bajo los principios de **Zero-Knowledge Architecture**, criptografía nativa en cliente (**Web Crypto API**) y autenticación biométrica de hardware (**WebAuthn API**).

Compatible al 100% con **macOS, Windows, Android e iOS**. No requiere servidores externos ni almacena contraseñas en texto plano en la nube.

---

## 🧭 Distinción Obligatoria de Terminología

En todo el diseño, documentación e interfaz de este sistema se mantiene estrictamente la siguiente convención técnica:

1. **Usuario / Operador:** Persona física responsable que opera, administra y desbloquea el sistema local mediante su **Huella Digital** o **Contraseña Maestra**.
2. **User / Contraseña:** Identificador de cuenta (*username*, correo o usuario de acceso) y clave secreta perteneciente a plataformas, programas externos, bases de datos o servicios en la nube guardados en la bóveda.

---

## 🔒 Arquitectura Criptográfica y de Seguridad

| Componente | Especificación Técnica | Propósito de Seguridad |
| :--- | :--- | :--- |
| **Cifrado en Reposo** | `AES-GCM` de 256 bits | Cifrado simétrico autenticado. Si un solo bit es manipulado, el descifrado falla de inmediato. |
| **Vector de Inicialización (IV)** | 12 bytes (96 bits) CSPRNG | Cada credencial se cifra con un IV fresco y único generado con `crypto.getRandomValues()`. |
| **Derivación de Clave** | `PBKDF2` (HMAC-SHA-256) | Deriva la clave de 256 bits a partir de la contraseña maestra del **Usuario/Operador** usando **100.000 iteraciones** y sal criptográfica de 16 bytes. |
| **Verificación de Clave** | Token cifrado de integridad | La contraseña maestra **nunca se almacena en disco** ni en hashes planos. Se verifica descifrando un token autenticado. |
| **Persistencia** | `IndexedDB` nativo | Almacenamiento local aislado en el navegador del cliente (`vault_meta` y `credentials`). |
| **Bloqueo por Inactividad** | Temporizador de inactividad configurable | Si el **Usuario/Operador** deja de interactuar por el tiempo configurado (ej: 10 min), la clave en memoria y los datos en claro se purgan de inmediato. |
| **Biometría de Hardware** | `WebAuthn API` (Platform Authenticator) | Enlaza la clave criptográfica local con el sensor físico (**Touch ID, Windows Hello, Face ID / huella**). |

---

## 🌟 Soporte Biométrico Nativo e Ingreso Dual

La pantalla de desbloqueo presenta **dos métodos claros de acceso**:
1. 👆 **Por Huella Digital / Biometría:** Utiliza el sensor nativo del equipo (**Touch ID** en Mac, **Windows Hello** en PC o lector de huellas/rostro en Android e iOS). Desbloquea la bóveda en 1 segundo sin tener que escribir.
2. 🔑 **Por Contraseña Maestra:** Si prefieres escribir o el equipo no cuenta con lector biométrico, puedes introducir tu clave maestra de siempre.
3. 🔄 **Alternancia fluida:** Pestañas directas en pantalla para alternar de método en cualquier momento.

---

## 🚀 Instalación y Ejecución por Plataforma

### 🍎 1. macOS (MacBook Air, MacBook Pro, iMac)
- **Opción A (Instalador DMG Oficial):**
  1. Descarga `Custodio-Credenciales-macOS.dmg` desde la carpeta `releases/`.
  2. Haz doble clic en el DMG y arrastra **Custodio Credenciales.app** a tu carpeta de **Aplicaciones**.
  3. ¡Listo! Ábrelo desde Launchpad, Aplicaciones o Spotlight y entra con tu sensor **Touch ID**.
- **Opción B (Instalador en 1 clic):**
  1. Abre la carpeta `macos/` y haz doble clic en `Instalar_en_Mac.command`.
  2. Copiará la app a Aplicaciones y creará un acceso directo en tu Escritorio.

---

### 🪟 2. Windows (10 / 11)
1. Abre la carpeta `windows/`.
2. Haz doble clic en **`Instalar_en_Windows.bat`**.
3. El instalador copiará la aplicación en tu sistema y creará un acceso directo en tu Escritorio llamado **"Custodio Credenciales"**.
4. Ábrelo desde el Escritorio: se ejecutará de forma silenciosa (sin dejar consolas negras abiertas) y podrás desbloquearlo con **Windows Hello** (huella o reconocimiento facial) o contraseña.
*(Para usarlo sin instalar, ejecuta `iniciar_portable_windows.bat`).*

---

### 📱 3. Android (Teléfonos y Tabletas)
- **Opción A (Instalador APK Nativo):**
  1. Descarga el archivo `custodio-credenciales.apk` desde `releases/` a tu teléfono Android.
  2. Toca el archivo `.apk` y selecciona **Instalar** (si es necesario, autoriza instalar apps desde archivos en Ajustes).
  3. ¡La app aparecerá en tu teléfono con su propio icono y soporte directo para el **lector de huellas**!
- **Opción B (PWA desde Chrome):**
  1. Abre el proyecto en Chrome en tu celular mediante la red Wi-Fi local o un servidor web.
  2. Toca los 3 puntitos de Chrome (⋮) y presiona **"Instalar aplicación"**.

---

### 🍏 4. iOS (iPhone y iPad)
1. Abre **Safari** en tu iPhone o iPad y navega a la URL de la aplicación (en tu red local o desplegada en GitHub Pages).
2. Toca el botón **Compartir** de Safari (el cuadrado con la flecha hacia arriba: ⎋ / ⤤).
3. Selecciona **"Agregar a la pantalla de inicio"** *(Add to Home Screen)*.
4. Toca **"Agregar"**. La app se instalará en tu pantalla de inicio, funcionará **100% offline** y te permitirá ingresar con **Face ID** o **Touch ID**.

---

## 📁 Estructura del Repositorio

```
custodio-vault-repo/
├── .github/
│   └── workflows/
│       └── deploy-pages.yml      # CI/CD para GitHub Pages
├── .gitignore                    # Filtro de archivos temporales
├── LICENSE                       # Licencia MIT
├── README.md                     # Documentación principal
├── index.html                    # Entrada directa (soporte GitHub Pages)
├── manifest.json                 # Manifiesto PWA
├── sw.js                         # Service Worker offline
├── css/
│   └── styles.css                # Estilos y reporte @media print
├── js/
│   ├── crypto.js                 # Motor criptográfico Web Crypto
│   ├── db.js                     # Base de datos IndexedDB
│   ├── biometrics.js             # Módulo WebAuthn
│   └── app.js                    # Controlador de interfaz
├── icons/
│   └── icon.svg                  # Icono vectorial
├── web/                          # Copia modular para despliegue web
├── macos/                        # Instalador y app bundle para macOS
├── windows/                      # Instalador y lanzador para Windows
├── android/                      # Código fuente completo Android Studio
├── ios/                          # Guía de instalación y assets para iOS
└── releases/                     # Binarios compilados listos para descargar
    ├── Custodio-Credenciales-macOS.dmg
    ├── instalador-mac.zip
    ├── instalador-windows.zip
    ├── custodio-credenciales.apk
    └── instalador-android.zip
```

---

## 💾 Respaldo y Restauración Cifrada (Backup & Restore)
- **Exportación:** Genera un archivo `.json` que contiene todos los registros cifrados íntegramente con tu contraseña maestra.
- **Importación:** Permite restaurar o fusionar credenciales en cualquier otro equipo con verificación automática de integridad.

---

## 🖨️ Reportes e Impresión de Auditoría (`@media print`)
La aplicación cuenta con una vista especializada para impresión en papel o PDF:
- Respeta los filtros y búsquedas en tiempo real.
- Opción de ocultar contraseñas (`••••••••`) para auditorías de inventario o mostrarlas en claro para planes de contingencia.
- Formato limpio corporativo sin menús ni botones de pantalla.
