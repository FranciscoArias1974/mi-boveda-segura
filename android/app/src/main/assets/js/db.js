/**
 * ============================================================================
 * ARCHIVO: js/db.js
 * SISTEMA: Gestor y Custodio Local de Credenciales (Secure Vault)
 * DESCRIPCIÓN: Capa de persistencia local basada en IndexedDB.
 *              Gestiona el almacenamiento seguro at-rest de metadatos de bóveda
 *              y registros cifrados de credenciales externas (User/Contraseña).
 * ============================================================================
 */

/* ==========================================================================
   SECCIÓN 1: CONSTANTES DE CONFIGURACIÓN Y DEFINICIÓN DEL ESQUEMA
   ========================================================================== */

const DB_NAME = 'SecureCredentialVaultDB';
const DB_VERSION = 1;

export const STORES = {
    META: 'vault_meta',
    CREDENTIALS: 'credentials'
};

/* ==========================================================================
   SECCIÓN 2: INICIALIZACIÓN Y GESTIÓN DE CONEXIÓN INDEXEDDB
   ========================================================================== */

let dbInstance = null;

/**
 * Abre o recupera la conexión activa a la base de datos IndexedDB.
 * @returns {Promise<IDBDatabase>}
 */
export function openVaultDB() {
    return new Promise((resolve, reject) => {
        if (dbInstance) {
            resolve(dbInstance);
            return;
        }

        const request = window.indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;

            // 1. Almacén de metadatos del Vault (sal criptográfica, verificador, ajustes)
            if (!db.objectStoreNames.contains(STORES.META)) {
                db.createObjectStore(STORES.META, { keyPath: 'key' });
            }

            // 2. Almacén de credenciales cifradas (Zero-Knowledge at rest)
            if (!db.objectStoreNames.contains(STORES.CREDENTIALS)) {
                const credStore = db.createObjectStore(STORES.CREDENTIALS, { keyPath: 'id' });
                credStore.createIndex('updatedAt', 'updatedAt', { unique: false });
                credStore.createIndex('createdAt', 'createdAt', { unique: false });
            }
        };

        request.onsuccess = (event) => {
            dbInstance = event.target.result;
            dbInstance.onversionchange = () => {
                dbInstance.close();
                dbInstance = null;
            };
            resolve(dbInstance);
        };

        request.onerror = (event) => {
            reject(new Error(`Error al abrir IndexedDB: ${event.target.error}`));
        };
    });
}

/* ==========================================================================
   SECCIÓN 3: GESTIÓN DE METADATOS Y ESTADO DE INICIALIZACIÓN
   ========================================================================== */

/**
 * Determina si el almacén ya fue inicializado por el Usuario/Operador con una contraseña maestra.
 * @returns {Promise<boolean>}
 */
export async function isVaultInitialized() {
    const salt = await getVaultMeta('salt');
    const integrityToken = await getVaultMeta('integrity_token');
    return Boolean(salt && integrityToken);
}

/**
 * Guarda un elemento en el almacén de metadatos del Vault.
 * @param {string} key
 * @param {any} value
 * @returns {Promise<void>}
 */
export async function saveVaultMeta(key, value) {
    const db = await openVaultDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORES.META], 'readwrite');
        const store = transaction.objectStore(STORES.META);
        const request = store.put({ key, value, updatedAt: new Date().toISOString() });

        request.onsuccess = () => resolve();
        request.onerror = (event) => reject(event.target.error);
    });
}

/**
 * Recupera un valor de metadatos a partir de su clave.
 * @param {string} key
 * @returns {Promise<any|null>}
 */
export async function getVaultMeta(key) {
    const db = await openVaultDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORES.META], 'readonly');
        const store = transaction.objectStore(STORES.META);
        const request = store.get(key);

        request.onsuccess = () => {
            resolve(request.result ? request.result.value : null);
        };
        request.onerror = (event) => reject(event.target.error);
    });
}

/* ==========================================================================
   SECCIÓN 4: OPERACIONES CRUD PARA REGISTROS DE CREDENCIALES (Cifradas)
   ========================================================================== */

/**
 * Guarda o actualiza un registro de credencial cifrada en IndexedDB.
 * @param {{ id: string, encryptedData: { iv: string, ciphertext: string }, createdAt: string, updatedAt: string }} record
 * @returns {Promise<void>}
 */
export async function saveEncryptedCredential(record) {
    const db = await openVaultDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORES.CREDENTIALS], 'readwrite');
        const store = transaction.objectStore(STORES.CREDENTIALS);
        const request = store.put(record);

        request.onsuccess = () => resolve();
        request.onerror = (event) => reject(event.target.error);
    });
}

/**
 * Obtiene todos los registros cifrados almacenados en IndexedDB.
 * @returns {Promise<Array<{ id: string, encryptedData: { iv: string, ciphertext: string }, createdAt: string, updatedAt: string }>>}
 */
export async function getAllEncryptedCredentials() {
    const db = await openVaultDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORES.CREDENTIALS], 'readonly');
        const store = transaction.objectStore(STORES.CREDENTIALS);
        const request = store.getAll();

        request.onsuccess = () => resolve(request.result || []);
        request.onerror = (event) => reject(event.target.error);
    });
}

/**
 * Elimina una credencial por su identificador único (UUID).
 * @param {string} id
 * @returns {Promise<void>}
 */
export async function deleteEncryptedCredential(id) {
    const db = await openVaultDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORES.CREDENTIALS], 'readwrite');
        const store = transaction.objectStore(STORES.CREDENTIALS);
        const request = store.delete(id);

        request.onsuccess = () => resolve();
        request.onerror = (event) => reject(event.target.error);
    });
}

/**
 * Limpia todas las credenciales del almacén (utilizado en restauración de respaldos).
 * @returns {Promise<void>}
 */
export async function clearAllCredentials() {
    const db = await openVaultDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORES.CREDENTIALS], 'readwrite');
        const store = transaction.objectStore(STORES.CREDENTIALS);
        const request = store.clear();

        request.onsuccess = () => resolve();
        request.onerror = (event) => reject(event.target.error);
    });
}

/* ==========================================================================
   SECCIÓN 5: RESTABLECIMIENTO Y DESTRUCCIÓN TOTAL DE DATOS
   ========================================================================== */

/**
 * Destruye la base de datos completa. Acción irreversible que elimina
 * todas las credenciales y configuración del Usuario/Operador.
 * @returns {Promise<void>}
 */
export function destroyVaultDatabase() {
    return new Promise((resolve, reject) => {
        if (dbInstance) {
            dbInstance.close();
            dbInstance = null;
        }

        const request = window.indexedDB.deleteDatabase(DB_NAME);
        request.onsuccess = () => resolve();
        request.onerror = (event) => reject(event.target.error);
        request.onblocked = () => {
            console.warn('La eliminación de la base de datos está bloqueada por otras conexiones abiertas.');
            resolve();
        };
    });
}
