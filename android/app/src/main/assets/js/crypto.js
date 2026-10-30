/**
 * ============================================================================
 * ARCHIVO: js/crypto.js
 * SISTEMA: Gestor y Custodio Local de Credenciales (Secure Vault)
 * DESCRIPCIÓN: Módulo criptográfico nativo basado en Web Crypto API.
 *              Implementa derivación de claves PBKDF2, cifrado/descifrado
 *              autenticado AES-GCM de 256 bits, generador de contraseñas
 *              seguro y validación de integridad de sesión para el Usuario/Operador.
 * ============================================================================
 */

/* ==========================================================================
   SECCIÓN 1: CONSTANTES CRIPTOGRÁFICAS Y VERIFICACIÓN DE ENTORNO SEGURO
   ========================================================================== */

const CRYPTO_CONFIG = {
    PBKDF2_ITERATIONS: 100000,
    SALT_BYTE_LENGTH: 16,
    IV_BYTE_LENGTH: 12, // 96 bits recomendado para AES-GCM
    AES_KEY_LENGTH: 256,
    HASH_ALGORITHM: 'SHA-256',
    INTEGRITY_CHECK_PHRASE: 'VAULT_INTEGRITY_VERIFIED_OPERATOR_AUTH'
};

const globalObj = typeof window !== 'undefined' ? window : globalThis;

/**
 * Comprueba si el entorno de ejecución cuenta con Web Crypto API habilitada
 * y contexto seguro (HTTPS, localhost o file:// según navegador).
 * @returns {boolean}
 */
export function isCryptoSubtleAvailable() {
    return typeof globalObj !== 'undefined' &&
           globalObj.crypto &&
           Boolean(globalObj.crypto.subtle);
}

/* ==========================================================================
   SECCIÓN 2: UTILIDADES DE CODIFICACIÓN (ArrayBuffer <-> Base64 / Hex / UTF-8)
   ========================================================================== */

/**
 * Convierte un ArrayBuffer o Uint8Array a cadena Base64
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function bufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return globalObj.btoa(binary);
}

/**
 * Convierte una cadena Base64 a Uint8Array
 * @param {string} base64String
 * @returns {Uint8Array}
 */
export function base64ToBuffer(base64String) {
    const binary = globalObj.atob(base64String);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convierte una cadena UTF-8 a Uint8Array
 * @param {string} str
 * @returns {Uint8Array}
 */
export function stringToBuffer(str) {
    return new TextEncoder().encode(str);
}

/**
 * Convierte un ArrayBuffer o Uint8Array a cadena UTF-8
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function bufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

/**
 * Genera bytes criptográficamente aleatorios
 * @param {number} length Número de bytes
 * @returns {Uint8Array}
 */
export function generateRandomBytes(length) {
    const bytes = new Uint8Array(length);
    globalObj.crypto.getRandomValues(bytes);
    return bytes;
}

/* ==========================================================================
   SECCIÓN 3: DERIVACIÓN DE CLAVES (PBKDF2 -> AES-GCM 256 bits)
   ========================================================================== */

/**
 * Deriva una CryptoKey AES-GCM a partir de la contraseña maestra del Usuario/Operador.
 * Utiliza PBKDF2 con HMAC-SHA-256 y un mínimo de 100.000 iteraciones.
 * 
 * @param {string} masterPassword - Contraseña maestra introducida por el Usuario/Operador
 * @param {Uint8Array} salt - Sal criptográfica de 16 bytes
 * @param {number} [iterations=100000] - Cantidad de iteraciones
 * @returns {Promise<CryptoKey>} Clave criptográfica para operaciones AES-GCM
 */
export async function deriveMasterKey(masterPassword, salt, iterations = CRYPTO_CONFIG.PBKDF2_ITERATIONS) {
    if (!isCryptoSubtleAvailable()) {
        throw new Error('Web Crypto API no está disponible en este entorno. Se requiere un contexto seguro (HTTPS o localhost).');
    }

    // 1. Importar la contraseña del Usuario/Operador como clave base cruda
    const passwordBuffer = stringToBuffer(masterPassword);
    const baseKey = await globalObj.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    // 2. Derivar la clave simétrica AES-GCM de 256 bits
    const derivedKey = await globalObj.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: CRYPTO_CONFIG.HASH_ALGORITHM
        },
        baseKey,
        {
            name: 'AES-GCM',
            length: CRYPTO_CONFIG.AES_KEY_LENGTH
        },
        false, // No extraíble de la memoria para prevenir fugas
        ['encrypt', 'decrypt']
    );

    return derivedKey;
}

/* ==========================================================================
   SECCIÓN 4: CIFRADO Y DESCIFRADO AUTENTICADO (AES-GCM)
   ========================================================================== */

/**
 * Cifra un objeto o cadena utilizando AES-GCM con IV único de 12 bytes.
 * 
 * @param {object|string} data - Datos sensibles a custodiar (Servicio, User, Contraseña, etc.)
 * @param {CryptoKey} cryptoKey - Clave AES-GCM derivada
 * @returns {Promise<{ iv: string, ciphertext: string }>} Payload cifrado en Base64
 */
export async function encryptPayload(data, cryptoKey) {
    const jsonString = typeof data === 'string' ? data : JSON.stringify(data);
    const plaintextBuffer = stringToBuffer(jsonString);

    // Generar un IV nuevo e irrepetible para cada registro
    const iv = generateRandomBytes(CRYPTO_CONFIG.IV_BYTE_LENGTH);

    const encryptedBuffer = await globalObj.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        cryptoKey,
        plaintextBuffer
    );

    return {
        iv: bufferToBase64(iv),
        ciphertext: bufferToBase64(encryptedBuffer)
    };
}

/**
 * Descifra y valida la autenticidad de un payload cifrado con AES-GCM.
 * Si el ciphertext o el tag de autenticación fue manipulado, falla automáticamente.
 * 
 * @param {{ iv: string, ciphertext: string }} payload - Objeto con IV y ciphertext en Base64
 * @param {CryptoKey} cryptoKey - Clave AES-GCM derivada
 * @returns {Promise<any>} Datos descifrados (objeto parseado o cadena)
 */
export async function decryptPayload(payload, cryptoKey) {
    if (!payload || !payload.iv || !payload.ciphertext) {
        throw new Error('Payload cifrado inválido o incompleto.');
    }

    const iv = base64ToBuffer(payload.iv);
    const encryptedBytes = base64ToBuffer(payload.ciphertext);

    const decryptedBuffer = await globalObj.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        cryptoKey,
        encryptedBytes
    );

    const jsonString = bufferToString(decryptedBuffer);
    try {
        return JSON.parse(jsonString);
    } catch {
        return jsonString;
    }
}

/* ==========================================================================
   SECCIÓN 5: VERIFICACIÓN DE INTEGRIDAD DEL VAULT (Autenticación del Usuario)
   ========================================================================== */

/**
 * Genera el token de verificación de integridad cifrado para registrar al Usuario/Operador.
 * Permite validar la contraseña maestra en futuros inicios de sesión sin guardarla jamás en texto claro.
 * 
 * @param {CryptoKey} cryptoKey
 * @returns {Promise<{ iv: string, ciphertext: string }>}
 */
export async function createIntegrityToken(cryptoKey) {
    const payload = {
        check: CRYPTO_CONFIG.INTEGRITY_CHECK_PHRASE,
        createdAt: new Date().toISOString()
    };
    return await encryptPayload(payload, cryptoKey);
}

/**
 * Verifica si la clave maestra ingresada por el Usuario/Operador es correcta.
 * Intenta descifrar el token de verificación almacenado en IndexedDB.
 * 
 * @param {{ iv: string, ciphertext: string }} storedToken
 * @param {CryptoKey} cryptoKey
 * @returns {Promise<boolean>} True si la clave es correcta y auténtica
 */
export async function verifyMasterKey(storedToken, cryptoKey) {
    try {
        const decrypted = await decryptPayload(storedToken, cryptoKey);
        return decrypted && decrypted.check === CRYPTO_CONFIG.INTEGRITY_CHECK_PHRASE;
    } catch (err) {
        // Fallo criptográfico: tag GCM inválido o clave incorrecta
        return false;
    }
}

/* ==========================================================================
   SECCIÓN 6: GENERADOR CRIPTOGRÁFICO DE CONTRASEÑAS SEGURAS (CSPRNG)
   ========================================================================== */

const CHAR_SETS = {
    uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ', // Sin caracteres confusos (I, O) por defecto
    lowercase: 'abcdefghijkmnopqrstuvwxyz', // Sin 'l' confusa
    numbers: '23456789',                    // Sin '0', '1' confusos
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

/**
 * Genera una contraseña de alta entropía utilizando el CSPRNG nativo.
 * Garantiza al menos un carácter de cada tipo seleccionado y mezcla uniforme.
 * 
 * @param {object} options
 * @param {number} [options.length=16]
 * @param {boolean} [options.useUppercase=true]
 * @param {boolean} [options.useLowercase=true]
 * @param {boolean} [options.useNumbers=true]
 * @param {boolean} [options.useSymbols=true]
 * @returns {{ password: string, entropy: number }}
 */
export function generateSecurePassword(options = {}) {
    const {
        length = 16,
        useUppercase = true,
        useLowercase = true,
        useNumbers = true,
        useSymbols = true
    } = options;

    let pool = '';
    const guaranteedChars = [];

    if (useUppercase) {
        pool += CHAR_SETS.uppercase;
        guaranteedChars.push(getRandomChar(CHAR_SETS.uppercase));
    }
    if (useLowercase) {
        pool += CHAR_SETS.lowercase;
        guaranteedChars.push(getRandomChar(CHAR_SETS.lowercase));
    }
    if (useNumbers) {
        pool += CHAR_SETS.numbers;
        guaranteedChars.push(getRandomChar(CHAR_SETS.numbers));
    }
    if (useSymbols) {
        pool += CHAR_SETS.symbols;
        guaranteedChars.push(getRandomChar(CHAR_SETS.symbols));
    }

    if (pool.length === 0) {
        pool = CHAR_SETS.lowercase + CHAR_SETS.numbers;
    }

    const remainingLength = Math.max(0, length - guaranteedChars.length);
    const randomChars = [];

    const randomBytes = generateRandomBytes(remainingLength);
    for (let i = 0; i < remainingLength; i++) {
        const index = randomBytes[i] % pool.length;
        randomChars.push(pool[index]);
    }

    // Combinar y mezclar con algoritmo Fisher-Yates usando CSPRNG
    const combined = guaranteedChars.concat(randomChars);
    for (let i = combined.length - 1; i > 0; i--) {
        const rand = generateRandomBytes(1)[0];
        const j = rand % (i + 1);
        [combined[i], combined[j]] = [combined[j], combined[i]];
    }

    const password = combined.join('');
    const entropy = Math.round(length * Math.log2(pool.length));

    return { password, entropy };
}

/**
 * Selecciona un carácter aleatorio seguro de una cadena dada
 * @param {string} charset
 * @returns {string}
 */
function getRandomChar(charset) {
    const byte = generateRandomBytes(1)[0];
    return charset[byte % charset.length];
}

/**
 * Evalúa la fortaleza cualitativa de una contraseña
 * @param {string} password
 * @returns {{ score: number, label: string, color: string }}
 */
export function evaluatePasswordStrength(password) {
    if (!password) return { score: 0, label: 'Vacía', color: '#94a3b8' };

    let score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    if (score <= 2) return { score: 1, label: 'Débil', color: '#ef4444' };
    if (score <= 4) return { score: 2, label: 'Moderada', color: '#f59e0b' };
    if (score <= 5) return { score: 3, label: 'Fuerte', color: '#10b981' };
    return { score: 4, label: 'Muy Fuerte', color: '#0284c7' };
}
