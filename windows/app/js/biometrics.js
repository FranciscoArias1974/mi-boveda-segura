/**
 * ============================================================================
 * ARCHIVO: js/biometrics.js
 * SISTEMA: Gestor y Custodio Local de Credenciales (Secure Vault)
 * DESCRIPCIÓN: Módulo de autenticación biométrica nativa (WebAuthn API).
 *              Permite el ingreso mediante Touch ID (macOS), Windows Hello
 *              (Windows) y sensores dactilares/faciales (Android / iOS).
 * ============================================================================
 */

import {
    bufferToBase64,
    base64ToBuffer,
    generateRandomBytes,
    stringToBuffer,
    bufferToString,
    encryptPayload,
    decryptPayload,
    deriveMasterKey
} from './crypto.js';

import { saveVaultMeta, getVaultMeta } from './db.js';

/* ==========================================================================
   SECCIÓN 1: DETECCIÓN DE HARDWARE Y SOPORTE BIOMÉTRICO
   ========================================================================== */

/**
 * Comprueba si el dispositivo actual cuenta con hardware biométrico disponible
 * (Touch ID, lector dactilar, Windows Hello, etc.) a través de WebAuthn.
 * @returns {Promise<boolean>}
 */
export async function isBiometricHardwareAvailable() {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
        return false;
    }

    try {
        if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            return Boolean(available);
        }
    } catch (err) {
        console.warn('Error al consultar sensor biométrico de plataforma:', err);
    }

    return false;
}

/**
 * Verifica si el Usuario/Operador ya tiene configurado el acceso biométrico en esta bóveda.
 * @returns {Promise<boolean>}
 */
export async function isBiometricsConfigured() {
    try {
        const bioConfig = await getVaultMeta('biometric_config');
        return Boolean(bioConfig && bioConfig.credentialId && bioConfig.wrappedPayload);
    } catch {
        return false;
    }
}

/* ==========================================================================
   SECCIÓN 2: REGISTRO DE CREDENCIAL BIOMÉTRICA (Touch ID / Windows Hello)
   ========================================================================== */

/**
 * Registra el sensor biométrico del sistema operativo para el Usuario/Operador
 * y genera una envoltura protegida para desbloquear la clave sin teclear.
 * 
 * @param {string} operatorName - Nombre del Usuario/Operador
 * @param {string} masterPassword - Contraseña maestra para asegurar la envoltura
 * @returns {Promise<boolean>} True si el registro fue completado con éxito
 */
export async function registerBiometricCredential(operatorName, masterPassword) {
    if (!await isBiometricHardwareAvailable()) {
        throw new Error('Tu equipo no tiene un lector de huella o biometría compatible con WebAuthn.');
    }

    // 1. Generar desafío criptográfico aleatorio
    const challenge = generateRandomBytes(32);
    const userId = generateRandomBytes(16);

    const relyingPartyId = window.location.hostname || 'localhost';

    const publicKeyCreationOptions = {
        challenge: challenge.buffer,
        rp: {
            name: 'Custodio Local de Credenciales',
            id: relyingPartyId
        },
        user: {
            id: userId.buffer,
            name: 'operador_local',
            displayName: operatorName || 'Usuario / Operador'
        },
        pubKeyCredParams: [
            { alg: -7, type: 'public-key' },   // ES256
            { alg: -257, type: 'public-key' }  // RS256
        ],
        authenticatorSelection: {
            authenticatorAttachment: 'platform', // Obliga al hardware integrado (Touch ID, Windows Hello)
            userVerification: 'required',        // Exige escaneo dactilar/biométrico obligatorio
            requireResidentKey: false
        },
        timeout: 60000
    };

    // 2. Invocar sensor biométrico del SO a través del navegador
    const credential = await navigator.credentials.create({
        publicKey: publicKeyCreationOptions
    });

    if (!credential) {
        throw new Error('La autenticación biométrica fue cancelada o no se reconoció el sensor.');
    }

    const credentialId = bufferToBase64(new Uint8Array(credential.rawId));

    // 3. Crear envoltura cifrada para la clave de bóveda
    // Derivamos una clave de dispositivo combinando el ID de la credencial biométrica
    // con una sal exclusiva del dispositivo
    const deviceSalt = generateRandomBytes(16);
    const deviceKey = await deriveMasterKey(credentialId, deviceSalt, 10000);

    // Cifrar la contraseña maestra del Usuario/Operador dentro de la envoltura protegida
    const wrappedPayload = await encryptPayload({ masterPassword }, deviceKey);

    // 4. Guardar configuración biométrica en IndexedDB (vault_meta)
    await saveVaultMeta('biometric_config', {
        credentialId: credentialId,
        deviceSalt: bufferToBase64(deviceSalt),
        wrappedPayload: wrappedPayload,
        enabledAt: new Date().toISOString(),
        operatorName: operatorName
    });

    return true;
}

/* ==========================================================================
   SECCIÓN 3: AUTENTICACIÓN Y DESBLOQUEO POR HUELLA DIGITAL
   ========================================================================== */

/**
 * Solicita la huella digital al Usuario/Operador mediante el sistema operativo
 * y recupera la contraseña maestra para abrir la bóveda de forma segura.
 * 
 * @returns {Promise<string>} Contraseña maestra recuperada tras la confirmación dactilar
 */
export async function authenticateWithBiometrics() {
    const bioConfig = await getVaultMeta('biometric_config');
    if (!bioConfig || !bioConfig.credentialId) {
        throw new Error('La autenticación biométrica no está configurada en este equipo.');
    }

    const credentialIdBytes = base64ToBuffer(bioConfig.credentialId);
    const challenge = generateRandomBytes(32);
    const relyingPartyId = window.location.hostname || 'localhost';

    const publicKeyRequestOptions = {
        challenge: challenge.buffer,
        rpId: relyingPartyId,
        allowCredentials: [{
            id: credentialIdBytes.buffer,
            type: 'public-key',
            transports: ['internal']
        }],
        userVerification: 'required', // Obliga al escaneo biométrico
        timeout: 60000
    };

    // 1. Invocar el diálogo nativo de Touch ID / Windows Hello / Sensor dactilar
    const assertion = await navigator.credentials.get({
        publicKey: publicKeyRequestOptions
    });

    if (!assertion) {
        throw new Error('Verificación biométrica rechazada o cancelada.');
    }

    // 2. Hardware validado: derivar clave local y desenvolver la contraseña maestra
    const deviceSalt = base64ToBuffer(bioConfig.deviceSalt);
    const deviceKey = await deriveMasterKey(bioConfig.credentialId, deviceSalt, 10000);

    const decrypted = await decryptPayload(bioConfig.wrappedPayload, deviceKey);

    if (!decrypted || !decrypted.masterPassword) {
        throw new Error('Error de integridad al recuperar la envoltura biométrica.');
    }

    return decrypted.masterPassword;
}

/* ==========================================================================
   SECCIÓN 4: DESVINCULACIÓN Y ELIMINACIÓN DE BIOMETRÍA
   ========================================================================== */

/**
 * Elimina la configuración biométrica de la bóveda local
 * @returns {Promise<void>}
 */
export async function disableBiometrics() {
    await saveVaultMeta('biometric_config', null);
}
