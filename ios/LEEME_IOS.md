# 🍏 Guía de Instalación y Uso en iOS (iPhone y iPad)

El **Custodio Local de Credenciales** es 100% compatible con **iOS (iPhone y iPad)** mediante la tecnología estándar **Progressive Web App (PWA)** y la **WebAuthn API** nativa de Apple.

---

## 🔒 Características en iOS
- **Acceso Biométrico Nativo:** Desbloqueo mediante **Face ID** o **Touch ID**.
- **100% Autónomo y Offline:** Al instalarse en la pantalla de inicio, el *Service Worker* almacena todo el código localmente en el dispositivo. No requiere conexión a internet para abrir la bóveda ni consultar contraseñas.
- **Experiencia de Aplicación Nativa:** Funciona en pantalla completa sin barra de direcciones, sin botones de Safari y con su propio icono de alta resolución.
- **Cifrado en Reposo:** Cifrado militar **AES-GCM de 256 bits** y derivación **PBKDF2** ejecutados dentro del motor WebKit de tu iPhone/iPad.

---

## 📲 Pasos para Instalar en iPhone o iPad

### Opción A: A través de tu Red Wi-Fi Local (Sin subir a internet)
1. Inicia el servidor local en tu computadora (Mac o Windows) conectada a la misma red Wi-Fi:
   - En Mac: ejecuta `compartir_para_android.command` (funciona igual para iOS) o `python3 -m http.server 8000 --bind 0.0.0.0`.
   - En Windows: ejecuta `compartir_para_android.bat`.
2. En tu iPhone o iPad, abre **Safari**.
3. Escribe la dirección IP local de tu ordenador (ejemplo: `http://192.168.1.103:8000`).
4. Verás la pantalla de la bóveda. Ahora:
   1. Toca el botón **Compartir** en la barra inferior de Safari (el icono del cuadrado con una flecha hacia arriba: ⎋ / ⤤).
   2. Desplázate hacia abajo y selecciona: **"Agregar a la pantalla de inicio"** *(Add to Home Screen)*.
   3. Confirma el nombre **Custodio** y toca **"Agregar"** en la esquina superior derecha.
5. ¡Listo! Se creará el icono de **Custodio** en tu pantalla de inicio junto a tus demás aplicaciones. Ya puedes apagar la computadora; la aplicación seguirá abriéndose de forma independiente y offline en tu iPhone/iPad.

---

### Opción B: A través de GitHub Pages (Recomendado para sincronización en la nube privada)
1. Sube este repositorio a tu cuenta de GitHub (como repositorio público o privado).
2. En la configuración del repositorio en GitHub, ve a **Settings** -> **Pages**.
3. En **Branch**, selecciona `main` y la carpeta `/ (root)`.
4. GitHub te dará un enlace seguro HTTPS (por ejemplo: `https://tu-usuario.github.io/custodio-vault/`).
5. Abre ese enlace en **Safari en tu iPhone/iPad**.
6. Toca el botón **Compartir** -> **"Agregar a la pantalla de inicio"**.
7. ¡Tendrás la aplicación instalada para siempre, con HTTPS seguro y soporte completo de **Face ID / Touch ID**!
