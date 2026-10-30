/**
 * ============================================================================
 * ARCHIVO: js/app.js
 * SISTEMA: Gestor y Custodio Local de Credenciales (Secure Vault)
 * DESCRIPCIÓN: Controlador principal de la aplicación. Gestiona el ciclo de
 *              vida de la sesión, temporizadores de inactividad, interacción
 *              UI, operaciones CRUD cifradas, búsqueda en tiempo real,
 *              portapapeles seguro, respaldos y reportes para impresión.
 * ============================================================================
 */

import {
    isCryptoSubtleAvailable,
    bufferToBase64,
    base64ToBuffer,
    generateRandomBytes,
    deriveMasterKey,
    encryptPayload,
    decryptPayload,
    createIntegrityToken,
    verifyMasterKey,
    generateSecurePassword,
    evaluatePasswordStrength
} from './crypto.js';

import {
    isVaultInitialized,
    saveVaultMeta,
    getVaultMeta,
    saveEncryptedCredential,
    getAllEncryptedCredentials,
    deleteEncryptedCredential,
    clearAllCredentials,
    destroyVaultDatabase
} from './db.js';

import {
    isBiometricHardwareAvailable,
    isBiometricsConfigured,
    registerBiometricCredential,
    authenticateWithBiometrics,
    disableBiometrics
} from './biometrics.js';

/* ==========================================================================
   SECCIÓN 1: ESTADO GLOBAL DE LA APLICACIÓN EN MEMORIA (Zero-Knowledge)
   ========================================================================== */

const state = {
    // Clave criptográfica AES-GCM derivada en memoria activa (se purga al bloquear)
    masterCryptoKey: null,
    // Caché en memoria de credenciales descifradas (se purga al bloquear)
    credentialsList: [],
    // Filtros activos
    searchQuery: '',
    selectedCategory: 'ALL',
    // Parámetros de la sesión del Usuario/Operador
    operatorName: 'Operador Autorizado',
    inactivityMinutes: 10,
    inactivityRemainingSeconds: 600,
    inactivityTimerId: null,
    // Estado de respaldos en espera
    pendingImportData: null,
    // Estado biométrico del hardware local
    hasBiometricHardware: false,
    isBiometricsActive: false
};

/* ==========================================================================
   SECCIÓN 2: INICIALIZACIÓN DEL SISTEMA (Bootstrap)
   ========================================================================== */

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Verificación obligatoria de compatibilidad con Web Crypto API
    if (!isCryptoSubtleAvailable()) {
        showToast('Web Crypto API no disponible. Ejecuta en contexto seguro (localhost o HTTPS).', 'danger', 10000);
        alert('Error Crítico de Seguridad: Tu navegador o entorno no soporta Web Crypto API en este contexto. Para ejecutar localmente, abre la aplicación vía localhost (ej: python -m http.server 8000) o un servidor web local con HTTPS.');
        return;
    }

    // 2. Detección de hardware biométrico (Touch ID, Windows Hello, etc.)
    state.hasBiometricHardware = await isBiometricHardwareAvailable();
    state.isBiometricsActive = await isBiometricsConfigured();

    const onboardingBioBox = document.getElementById('onboarding-bio-box');
    if (onboardingBioBox && state.hasBiometricHardware) {
        onboardingBioBox.style.display = 'block';
    }

    // 3. Comprobar si el Almacén ya fue inicializado previamente por el Usuario/Operador
    try {
        const initialized = await isVaultInitialized();
        const authScreen = document.getElementById('auth-screen');
        const onboardingForm = document.getElementById('onboarding-form');
        const unlockContainer = document.getElementById('unlock-container');
        const authTitle = document.getElementById('auth-title');
        const authSubtitle = document.getElementById('auth-subtitle');

        authScreen.style.display = 'flex';

        if (!initialized) {
            // Caso A: Primera vez que el Usuario/Operador usa la aplicación
            authTitle.textContent = 'Configuración Inicial del Custodio';
            authSubtitle.textContent = 'Establece tu Contraseña Maestra como Usuario / Operador';
            onboardingForm.style.display = 'block';
            unlockContainer.style.display = 'none';
        } else {
            // Caso B: El almacén ya existe; configurar pantalla de desbloqueo dual
            authTitle.textContent = 'Custodio Local Bloqueado';
            authSubtitle.textContent = 'Selecciona tu método de ingreso: Huella Digital o Contraseña';
            onboardingForm.style.display = 'none';
            unlockContainer.style.display = 'block';

            configureUnlockViewMode();
        }

        // Cargar ajustes guardados previamente (si existen)
        const savedSettings = await getVaultMeta('settings');
        if (savedSettings) {
            state.operatorName = savedSettings.operatorName || state.operatorName;
            state.inactivityMinutes = Number(savedSettings.inactivityTimeoutMinutes) || 10;
            state.inactivityRemainingSeconds = state.inactivityMinutes * 60;
            updateOperatorLabelUI();
        }
    } catch (err) {
        console.error('Error durante la inicialización de la bóveda:', err);
        showToast('Error al acceder a IndexedDB: ' + err.message, 'danger');
    }

    // 4. Registrar escuchadores de eventos
    setupEventListeners();
});

/**
 * Configura la vista de desbloqueo inicial según disponibilidad biométrica
 */
function configureUnlockViewMode() {
    const tabBiometric = document.getElementById('tab-btn-biometric');
    const tabPassword = document.getElementById('tab-btn-password');
    const bioSection = document.getElementById('unlock-biometric-section');
    const passForm = document.getElementById('unlock-form');
    const tabsContainer = document.getElementById('auth-method-tabs');

    if (state.isBiometricsActive && state.hasBiometricHardware) {
        // Huella disponible y activa: mostrar ambas pestañas con Huella seleccionada
        if (tabsContainer) tabsContainer.style.display = 'flex';
        tabBiometric?.classList.add('active');
        tabPassword?.classList.remove('active');
        if (bioSection) bioSection.style.display = 'flex';
        if (passForm) passForm.style.display = 'none';
    } else {
        // Huella no activa: mostrar Contraseña por defecto
        if (!state.hasBiometricHardware && tabsContainer) {
            tabsContainer.style.display = 'none';
        }
        tabPassword?.classList.add('active');
        tabBiometric?.classList.remove('active');
        if (bioSection) bioSection.style.display = 'none';
        if (passForm) passForm.style.display = 'block';
        document.getElementById('unlock-password')?.focus();
    }
}

/* ==========================================================================
   SECCIÓN 3: GESTIÓN DE SESIÓN Y BLOQUEO POR INACTIVIDAD
   ========================================================================== */

/**
 * Reinicia el contador de inactividad ante cualquier interacción del Usuario/Operador
 */
function resetInactivityCountdown() {
    if (!state.masterCryptoKey) return;
    state.inactivityRemainingSeconds = state.inactivityMinutes * 60;
    updateInactivityDisplay();
}

/**
 * Inicia el temporizador de cuenta regresiva de inactividad
 */
function startInactivityMonitor() {
    stopInactivityMonitor();
    state.inactivityRemainingSeconds = state.inactivityMinutes * 60;
    updateInactivityDisplay();

    state.inactivityTimerId = setInterval(() => {
        if (!state.masterCryptoKey) {
            stopInactivityMonitor();
            return;
        }

        state.inactivityRemainingSeconds--;
        updateInactivityDisplay();

        if (state.inactivityRemainingSeconds <= 0) {
            lockVaultSession(true);
        }
    }, 1000);
}

/**
 * Detiene el temporizador de inactividad
 */
function stopInactivityMonitor() {
    if (state.inactivityTimerId) {
        clearInterval(state.inactivityTimerId);
        state.inactivityTimerId = null;
    }
}

/**
 * Actualiza la visualización gráfica del tiempo restante de sesión
 */
function updateInactivityDisplay() {
    const display = document.getElementById('session-timer-display');
    if (!display) return;
    const mins = Math.floor(Math.max(0, state.inactivityRemainingSeconds) / 60);
    const secs = Math.max(0, state.inactivityRemainingSeconds) % 60;
    display.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    
    // Alerta visual si queda menos de 1 minuto
    if (state.inactivityRemainingSeconds <= 60) {
        display.style.backgroundColor = '#fee2e2';
        display.style.color = '#dc2626';
    } else {
        display.style.backgroundColor = '';
        display.style.color = '';
    }
}

/**
 * Bloquea la sesión y purga inmediatamente de la memoria toda información sensible
 * @param {boolean} [byInactivity=false] - Indica si el bloqueo fue automático por inactividad
 */
export function lockVaultSession(byInactivity = false) {
    stopInactivityMonitor();

    // Purga radical de memoria en cliente (Zero-Knowledge)
    state.masterCryptoKey = null;
    state.credentialsList = [];
    state.searchQuery = '';
    state.selectedCategory = 'ALL';
    state.pendingImportData = null;

    // Limpieza de campos sensibles en la interfaz
    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';
    const unlockPasswordInput = document.getElementById('unlock-password');
    if (unlockPasswordInput) unlockPasswordInput.value = '';

    // Cerrar cualquier modal abierto
    closeAllModals();

    // Mostrar pantalla de autenticación en modo desbloqueo
    const authScreen = document.getElementById('auth-screen');
    const onboardingForm = document.getElementById('onboarding-form');
    const unlockContainer = document.getElementById('unlock-container');
    const authTitle = document.getElementById('auth-title');
    const authSubtitle = document.getElementById('auth-subtitle');

    authTitle.textContent = 'Custodio Local Bloqueado';
    authSubtitle.textContent = byInactivity
        ? 'Sesión suspendida automáticamente por inactividad para proteger tus datos'
        : 'Selecciona tu método de ingreso: Huella Digital o Contraseña';

    onboardingForm.style.display = 'none';
    unlockContainer.style.display = 'block';
    authScreen.style.display = 'flex';

    configureUnlockViewMode();

    // Limpiar renderizado
    renderCredentialsGrid();

    if (byInactivity) {
        showToast('Bloqueo de seguridad: Sesión cerrada por inactividad.', 'warning', 5000);
    } else {
        showToast('Sesión cerrada. Memoria purgada exitosamente.', 'success', 3000);
    }
}

/* ==========================================================================
   SECCIÓN 4: FLUJOS DE AUTENTICACIÓN (Onboarding, Desbloqueo y Biometría)
   ========================================================================== */

/**
 * Configuración inicial del Usuario/Operador (Onboarding)
 */
async function handleOnboardingSubmit(event) {
    event.preventDefault();
    const passInput = document.getElementById('init-master-password');
    const confirmInput = document.getElementById('init-master-password-confirm');
    const timeoutSelect = document.getElementById('init-timeout-select');
    const enableBioCheck = document.getElementById('init-enable-biometrics');

    const password = passInput.value.trim();
    const confirm = confirmInput.value.trim();
    const timeout = Number(timeoutSelect.value) || 10;
    const wantsBiometrics = Boolean(enableBioCheck && enableBioCheck.checked);

    if (password.length < 10) {
        showToast('La contraseña maestra debe tener al menos 10 caracteres.', 'danger');
        return;
    }

    if (password !== confirm) {
        showToast('Las contraseñas maestras introducidas no coinciden.', 'danger');
        return;
    }

    try {
        // 1. Generar salt aleatorio seguro de 16 bytes
        const salt = generateRandomBytes(16);
        const saltBase64 = bufferToBase64(salt);

        // 2. Derivar la clave simétrica AES-GCM con 100.000 iteraciones
        const derivedKey = await deriveMasterKey(password, salt, 100000);

        // 3. Crear token de verificación de integridad cifrado
        const integrityToken = await createIntegrityToken(derivedKey);

        // 4. Persistir metadatos en IndexedDB
        await saveVaultMeta('salt', saltBase64);
        await saveVaultMeta('integrity_token', integrityToken);
        await saveVaultMeta('settings', {
            operatorName: 'Operador Principal',
            inactivityTimeoutMinutes: timeout,
            createdAt: new Date().toISOString()
        });

        // 5. Si el Usuario/Operador desea huella digital y el hardware lo soporta, registrar
        if (wantsBiometrics && state.hasBiometricHardware) {
            try {
                await registerBiometricCredential('Operador Principal', password);
                state.isBiometricsActive = true;
                showToast('Huella digital (Touch ID / Windows Hello) vinculada con éxito.', 'info', 4000);
            } catch (bioErr) {
                console.warn('Registro biométrico omitido o cancelado:', bioErr);
                showToast('Bóveda creada con tu contraseña maestra. Podrás activar la huella luego en Ajustes.', 'info', 4000);
            }
        }

        // 6. Establecer estado activo
        state.masterCryptoKey = derivedKey;
        state.inactivityMinutes = timeout;
        state.inactivityRemainingSeconds = timeout * 60;
        state.credentialsList = [];

        // Limpiar inputs del formulario
        passInput.value = '';
        confirmInput.value = '';

        // Ocultar overlay de autenticación
        document.getElementById('auth-screen').style.display = 'none';

        // Iniciar monitor de inactividad y renderizar vista
        startInactivityMonitor();
        updateOperatorLabelUI();
        renderCredentialsGrid();

        showToast('¡Bóveda configurada con éxito! Bienvenido, Usuario / Operador.', 'success', 5000);
    } catch (err) {
        console.error('Error al inicializar la bóveda:', err);
        showToast('Error al configurar la bóveda: ' + err.message, 'danger');
    }
}

/**
 * Realiza el proceso criptográfico de validación de clave y apertura de la bóveda
 * @param {string} password - Contraseña maestra introducida manualmente o recuperada vía huella digital
 * @returns {Promise<boolean>} True si el desbloqueo fue exitoso
 */
async function executeUnlockVault(password) {
    if (!password) {
        showToast('Ingresa tu contraseña maestra.', 'warning');
        return false;
    }

    const saltBase64 = await getVaultMeta('salt');
    const integrityToken = await getVaultMeta('integrity_token');

    if (!saltBase64 || !integrityToken) {
        throw new Error('Metadatos de bóveda no encontrados o dañados.');
    }

    const salt = base64ToBuffer(saltBase64);
    const derivedKey = await deriveMasterKey(password, salt, 100000);
    const isValid = await verifyMasterKey(integrityToken, derivedKey);

    if (!isValid) {
        showToast('Contraseña maestra incorrecta. Acceso denegado.', 'danger');
        return false;
    }

    // Clave verificada: Asignar a memoria y descifrar todas las credenciales
    state.masterCryptoKey = derivedKey;
    await loadAndDecryptAllCredentials();

    // Cargar ajustes
    const settings = await getVaultMeta('settings');
    if (settings) {
        state.operatorName = settings.operatorName || state.operatorName;
        state.inactivityMinutes = Number(settings.inactivityTimeoutMinutes) || 10;
    }

    // Limpiar campo de texto si se usó formulario
    const passInput = document.getElementById('unlock-password');
    if (passInput) passInput.value = '';

    // Ocultar pantalla de bloqueo
    document.getElementById('auth-screen').style.display = 'none';

    // Iniciar monitor de inactividad
    startInactivityMonitor();
    updateOperatorLabelUI();
    renderCredentialsGrid();

    return true;
}

/**
 * Desbloqueo de sesión mediante el formulario de contraseña maestra
 */
async function handleUnlockSubmit(event) {
    event.preventDefault();
    const unlockPasswordInput = document.getElementById('unlock-password');
    const password = unlockPasswordInput.value.trim();
    const btnSubmit = document.getElementById('btn-unlock-submit');

    if (!password) {
        showToast('Ingresa tu contraseña maestra.', 'warning');
        return;
    }

    btnSubmit.disabled = true;
    btnSubmit.innerHTML = '<span>Verificando y derivando clave...</span>';

    try {
        const success = await executeUnlockVault(password);
        if (success) {
            showToast(`Bóveda desbloqueada. ${state.credentialsList.length} credenciales cargadas en memoria.`, 'success');
        }
    } catch (err) {
        console.error('Error durante el desbloqueo:', err);
        showToast('Error al desbloquear: ' + err.message, 'danger');
    } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
            <span>Desbloquear Bóveda</span>
        `;
    }
}

/**
 * Desbloqueo de sesión mediante Huella Digital (Touch ID / Windows Hello / Android / iOS)
 */
async function handleBiometricLogin() {
    const statusMsg = document.getElementById('bio-status-msg');
    const triggerBtn = document.getElementById('btn-trigger-biometrics');
    if (statusMsg) statusMsg.textContent = 'Verificando huella digital en el dispositivo...';
    if (triggerBtn) triggerBtn.style.animationDuration = '0.8s';

    try {
        const masterPassword = await authenticateWithBiometrics();
        const success = await executeUnlockVault(masterPassword);
        if (success) {
            showToast(`¡Autenticación biométrica exitosa! Bienvenido, ${state.operatorName}.`, 'success');
        }
    } catch (err) {
        console.warn('Fallo en autenticación biométrica:', err);
        if (statusMsg) statusMsg.textContent = 'Toca el sensor o ingresa con tu contraseña';
        showToast('Verificación biométrica no completada o cancelada. Puedes reintentar o usar contraseña.', 'warning', 4500);
    } finally {
        if (triggerBtn) triggerBtn.style.animationDuration = '2.2s';
    }
}

/**
 * Carga todos los registros cifrados desde IndexedDB y los descifra hacia la memoria activa
 */
async function loadAndDecryptAllCredentials() {
    if (!state.masterCryptoKey) return;

    const encryptedRecords = await getAllEncryptedCredentials();
    const decryptedList = [];

    for (const record of encryptedRecords) {
        try {
            const data = await decryptPayload(record.encryptedData, state.masterCryptoKey);
            decryptedList.push({
                id: record.id,
                service: data.service || 'Servicio Sin Nombre',
                user: data.user || '',
                password: data.password || '',
                url: data.url || '',
                notes: data.notes || '',
                category: data.category || 'Otros',
                createdAt: record.createdAt,
                updatedAt: record.updatedAt
            });
        } catch (decryptErr) {
            console.warn(`No se pudo descifrar el registro ID ${record.id}:`, decryptErr);
        }
    }

    // Ordenar de más reciente a más antiguo
    decryptedList.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    state.credentialsList = decryptedList;
}

/**
 * Actualiza la etiqueta del Usuario/Operador en la cabecera
 */
function updateOperatorLabelUI() {
    const label = document.getElementById('session-operator-label');
    if (label) {
        label.textContent = state.operatorName || 'Usuario / Operador';
    }
}

/* ==========================================================================
   SECCIÓN 5: OPERACIONES CRUD DE CREDENCIALES (User / Contraseña)
   ========================================================================== */

/**
 * Abre el modal para registrar una nueva credencial externa
 */
function openNewCredentialModal() {
    document.getElementById('modal-cred-title').textContent = 'Registrar Nueva Credencial Externa';
    document.getElementById('cred-id').value = '';
    document.getElementById('cred-service').value = '';
    document.getElementById('cred-category').value = 'Web';
    document.getElementById('cred-user').value = '';
    document.getElementById('cred-password').value = '';
    document.getElementById('cred-url').value = '';
    document.getElementById('cred-notes').value = '';

    updateStrengthMeterUI('cred-password', 'cred-strength-bar', 'cred-strength-label', 'cred-strength-entropy');
    openModal('modal-credential');
    document.getElementById('cred-service').focus();
}

/**
 * Abre el modal para editar una credencial existente
 * @param {string} id
 */
function openEditCredentialModal(id) {
    const cred = state.credentialsList.find(c => c.id === id);
    if (!cred) return;

    document.getElementById('modal-cred-title').textContent = 'Modificar Credencial Externa';
    document.getElementById('cred-id').value = cred.id;
    document.getElementById('cred-service').value = cred.service;
    document.getElementById('cred-category').value = cred.category;
    document.getElementById('cred-user').value = cred.user;
    document.getElementById('cred-password').value = cred.password;
    document.getElementById('cred-url').value = cred.url;
    document.getElementById('cred-notes').value = cred.notes;

    updateStrengthMeterUI('cred-password', 'cred-strength-bar', 'cred-strength-label', 'cred-strength-entropy');
    openModal('modal-credential');
}

/**
 * Procesa el guardado (creación o actualización) de una credencial externa
 */
async function handleCredentialFormSubmit(event) {
    event.preventDefault();
    if (!state.masterCryptoKey) {
        showToast('Error de sesión: Bóveda no autenticada.', 'danger');
        return;
    }

    const id = document.getElementById('cred-id').value || crypto.randomUUID();
    const service = document.getElementById('cred-service').value.trim();
    const category = document.getElementById('cred-category').value;
    const user = document.getElementById('cred-user').value.trim();
    const password = document.getElementById('cred-password').value;
    const url = document.getElementById('cred-url').value.trim();
    const notes = document.getElementById('cred-notes').value.trim();

    if (!service || !user || !password) {
        showToast('Servicio, User y Contraseña son campos obligatorios.', 'warning');
        return;
    }

    try {
        const payloadToEncrypt = {
            service,
            category,
            user,
            password,
            url,
            notes
        };

        // 1. Cifrar con AES-GCM e IV fresco de 12 bytes
        const encryptedData = await encryptPayload(payloadToEncrypt, state.masterCryptoKey);

        const now = new Date().toISOString();
        const existingIndex = state.credentialsList.findIndex(c => c.id === id);
        const createdAt = existingIndex >= 0 ? state.credentialsList[existingIndex].createdAt : now;

        const recordToStore = {
            id,
            encryptedData,
            createdAt,
            updatedAt: now
        };

        // 2. Guardar en IndexedDB (cifrado en reposo)
        await saveEncryptedCredential(recordToStore);

        // 3. Actualizar memoria activa
        const updatedItem = {
            id,
            service,
            category,
            user,
            password,
            url,
            notes,
            createdAt,
            updatedAt: now
        };

        if (existingIndex >= 0) {
            state.credentialsList[existingIndex] = updatedItem;
        } else {
            state.credentialsList.unshift(updatedItem);
        }

        closeModal('modal-credential');
        renderCredentialsGrid();
        showToast(`Credencial para "${service}" guardada y cifrada exitosamente.`, 'success');
    } catch (err) {
        console.error('Error al guardar credencial:', err);
        showToast('Error al guardar credencial: ' + err.message, 'danger');
    }
}

/**
 * Elimina una credencial externa previa confirmación
 * @param {string} id
 */
async function handleDeleteCredential(id) {
    const cred = state.credentialsList.find(c => c.id === id);
    if (!cred) return;

    const confirmDelete = window.confirm(`¿Confirmas la eliminación definitiva de la credencial del servicio "${cred.service}" (User: ${cred.user})? Esta acción no se puede deshacer.`);
    if (!confirmDelete) return;

    try {
        await deleteEncryptedCredential(id);
        state.credentialsList = state.credentialsList.filter(c => c.id !== id);
        renderCredentialsGrid();
        showToast(`Credencial de "${cred.service}" eliminada.`, 'success');
    } catch (err) {
        console.error('Error al eliminar credencial:', err);
        showToast('Error al eliminar credencial: ' + err.message, 'danger');
    }
}

/* ==========================================================================
   SECCIÓN 6: BUSCADOR REACTIVO EN TIEMPO REAL Y RENDERIZADO
   ========================================================================== */

/**
 * Filtra las credenciales activas en memoria según búsqueda y categoría
 * @returns {Array<object>}
 */
function getFilteredCredentials() {
    return state.credentialsList.filter(item => {
        // Filtro de categoría
        const matchCategory = state.selectedCategory === 'ALL' || item.category === state.selectedCategory;
        if (!matchCategory) return false;

        // Filtro de texto en tiempo real (Servicio o User)
        if (!state.searchQuery) return true;

        const query = state.searchQuery.toLowerCase();
        const matchService = item.service.toLowerCase().includes(query);
        const matchUser = item.user.toLowerCase().includes(query);

        return matchService || matchUser;
    });
}

/**
 * Renderiza el catálogo de credenciales en pantalla
 */
function renderCredentialsGrid() {
    const container = document.getElementById('credentials-container');
    const emptyState = document.getElementById('empty-state');
    const emptyTitle = document.getElementById('empty-title');
    const emptyDesc = document.getElementById('empty-desc');
    const counterFiltered = document.getElementById('counter-filtered');
    const counterTotal = document.getElementById('counter-total');

    if (!container) return;

    const filtered = getFilteredCredentials();
    const total = state.credentialsList.length;

    if (counterFiltered) counterFiltered.textContent = filtered.length;
    if (counterTotal) counterTotal.textContent = total;

    if (filtered.length === 0) {
        container.style.display = 'none';
        emptyState.style.display = 'block';

        if (total === 0) {
            emptyTitle.textContent = 'La bóveda está vacía';
            emptyDesc.textContent = 'Comienza agregando tu primera credencial externa para mantenerla custodiada y cifrada localmente.';
        } else {
            emptyTitle.textContent = 'Sin coincidencias';
            emptyDesc.textContent = `No se hallaron credenciales que coincidan con "${state.searchQuery}" en la categoría seleccionada.`;
        }
        return;
    }

    emptyState.style.display = 'none';
    container.style.display = 'grid';

    container.innerHTML = filtered.map(item => {
        const firstLetter = item.service.charAt(0).toUpperCase() || '?';
        const hasUrl = Boolean(item.url && item.url.trim());
        const hasNotes = Boolean(item.notes && item.notes.trim());

        return `
            <article class="credential-card" data-id="${item.id}">
                <div class="card-header">
                    <div class="service-meta">
                        <div class="service-icon-badge" aria-hidden="true">${escapeHTML(firstLetter)}</div>
                        <div class="service-titles">
                            <h3 class="service-name" title="${escapeHTML(item.service)}">${escapeHTML(item.service)}</h3>
                            <span class="service-category-tag">${escapeHTML(item.category)}</span>
                        </div>
                    </div>
                </div>

                <div class="card-body">
                    <!-- Campo User -->
                    <div class="field-group">
                        <span class="field-label">User</span>
                        <div class="field-value-row">
                            <span class="field-text" title="${escapeHTML(item.user)}">${escapeHTML(item.user)}</span>
                            <div class="inline-actions">
                                <button type="button" class="btn-tiny btn-copy-user" data-user="${escapeAttr(item.user)}" title="Copiar User al portapapeles" aria-label="Copiar User">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                    <span>Copiar</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Campo Contraseña -->
                    <div class="field-group">
                        <span class="field-label">Contraseña</span>
                        <div class="field-value-row">
                            <span class="field-text password-masked" data-password="${escapeAttr(item.password)}">••••••••••••</span>
                            <div class="inline-actions">
                                <button type="button" class="btn-tiny btn-toggle-card-pass" title="Alternar visibilidad" aria-label="Alternar visibilidad de contraseña">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                </button>
                                <button type="button" class="btn-tiny btn-copy-pass" data-password="${escapeAttr(item.password)}" title="Copiar contraseña de forma segura" aria-label="Copiar Contraseña">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                    <span>Copiar</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Enlace URL (si aplica) -->
                    ${hasUrl ? `
                        <div class="field-group">
                            <span class="field-label">Enlace URL</span>
                            <div class="field-value-row" style="background: transparent; border: none; padding: 0.1rem 0;">
                                <a href="${escapeAttr(item.url)}" target="_blank" rel="noopener noreferrer" style="font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.35rem; word-break: break-all;">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                    <span>${escapeHTML(item.url)}</span>
                                </a>
                            </div>
                        </div>
                    ` : ''}

                    <!-- Notas confidenciales (si aplica) -->
                    ${hasNotes ? `
                        <div class="card-notes" title="Notas confidenciales">${escapeHTML(item.notes)}</div>
                    ` : ''}
                </div>

                <div class="card-footer">
                    <span>Act: ${formatDate(item.updatedAt)}</span>
                    <div class="card-actions">
                        <button type="button" class="btn-tiny btn-edit-cred" data-id="${item.id}" title="Editar credencial">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                            <span>Editar</span>
                        </button>
                        <button type="button" class="btn-tiny btn-delete-cred" data-id="${item.id}" title="Eliminar credencial" style="color: var(--danger);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            <span>Eliminar</span>
                        </button>
                    </div>
                </div>
            </article>
        `;
    }).join('');
}

/* ==========================================================================
   SECCIÓN 7: PORTAPAPELES SEGURO Y PROTECCIÓN DE DATOS
   ========================================================================== */

/**
 * Copia texto al portapapeles con confirmación visual
 * @param {string} text - Contenido a copiar
 * @param {string} labelName - Nombre legible ('User' o 'Contraseña')
 */
async function copyToClipboardSafe(text, labelName) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        if (labelName === 'Contraseña') {
            showToast('Contraseña copiada al portapapeles de forma segura.', 'success', 4000);
        } else {
            showToast(`${labelName} copiado al portapapeles.`, 'info', 3000);
        }
    } catch (err) {
        console.warn('Fallback al método alternativo de copiado:', err);
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast(`${labelName} copiado al portapapeles.`, 'info', 3000);
        } catch {
            showToast('No se pudo copiar automáticamente. Copia manualmente.', 'warning');
        } finally {
            document.body.removeChild(textarea);
        }
    }
}

/* ==========================================================================
   SECCIÓN 8: GENERADOR DE CONTRASEÑAS Y EVALUACIÓN DE FORTALEZA
   ========================================================================== */

function openPasswordGeneratorModal() {
    refreshGeneratedPassword();
    openModal('modal-generator');
}

function refreshGeneratedPassword() {
    const length = Number(document.getElementById('gen-length-range').value) || 20;
    const useUppercase = document.getElementById('gen-opt-uppercase').checked;
    const useLowercase = document.getElementById('gen-opt-lowercase').checked;
    const useNumbers = document.getElementById('gen-opt-numbers').checked;
    const useSymbols = document.getElementById('gen-opt-symbols').checked;

    const result = generateSecurePassword({ length, useUppercase, useLowercase, useNumbers, useSymbols });
    const display = document.getElementById('gen-result-display');
    const bar = document.getElementById('gen-strength-bar');
    const label = document.getElementById('gen-strength-label');
    const entropyDisplay = document.getElementById('gen-strength-entropy');

    if (display) display.textContent = result.password;

    const strength = evaluatePasswordStrength(result.password);
    if (bar) {
        bar.style.width = `${(strength.score / 4) * 100}%`;
        bar.style.backgroundColor = strength.color;
    }
    if (label) {
        label.textContent = strength.label;
        label.style.color = strength.color;
    }
    if (entropyDisplay) {
        entropyDisplay.textContent = `Entropía: ~${result.entropy} bits`;
    }
}

function updateStrengthMeterUI(inputId, barId, labelId, entropyId) {
    const input = document.getElementById(inputId);
    const bar = document.getElementById(barId);
    const label = document.getElementById(labelId);
    const entropyDisplay = document.getElementById(entropyId);
    if (!input || !bar || !label) return;

    const val = input.value;
    const strength = evaluatePasswordStrength(val);

    bar.style.width = `${(strength.score / 4) * 100}%`;
    bar.style.backgroundColor = strength.color;
    label.textContent = strength.label;
    label.style.color = strength.color;

    if (entropyDisplay) {
        const poolSize = (/[A-Z]/.test(val) ? 26 : 0) +
                         (/[a-z]/.test(val) ? 26 : 0) +
                         (/[0-9]/.test(val) ? 10 : 0) +
                         (/[^A-Za-z0-9]/.test(val) ? 32 : 0) || 1;
        const bits = Math.round(val.length * Math.log2(poolSize));
        entropyDisplay.textContent = `${bits} bits`;
    }
}

/* ==========================================================================
   SECCIÓN 9: REPORTES E IMPRESIÓN AUDITABLE (@media print)
   ========================================================================== */

function openPrintModal() {
    if (state.credentialsList.length === 0) {
        showToast('No hay credenciales registradas para generar un reporte.', 'warning');
        return;
    }
    openModal('modal-print-options');
}

/**
 * Prepara los datos del reporte de auditoría e invoca el cuadro de diálogo de impresión
 */
function executePrintReport() {
    const scope = document.getElementById('print-scope-select').value;
    const privacy = document.getElementById('print-privacy-select').value;

    const recordsToPrint = scope === 'filtered' ? getFilteredCredentials() : state.credentialsList;

    if (recordsToPrint.length === 0) {
        showToast('No hay credenciales en el alcance seleccionado para imprimir.', 'warning');
        return;
    }

    // Actualizar encabezado del reporte
    document.getElementById('print-meta-operator').textContent = state.operatorName || 'Usuario / Operador';
    document.getElementById('print-meta-date').textContent = new Date().toLocaleString('es-ES', {
        dateStyle: 'full',
        timeStyle: 'medium'
    });
    document.getElementById('print-meta-count').textContent = `${recordsToPrint.length} registros (${scope === 'filtered' ? 'filtrados' : 'totales'})`;

    // Inyectar filas en la tabla de impresión
    const tbody = document.getElementById('print-table-body');
    tbody.innerHTML = recordsToPrint.map((item, index) => {
        const passwordDisplay = privacy === 'unmasked' ? escapeHTML(item.password) : '••••••••••••';
        return `
            <tr>
                <td style="text-align: center; font-weight: 600;">${index + 1}</td>
                <td><strong>${escapeHTML(item.service)}</strong></td>
                <td class="code-cell">${escapeHTML(item.user)}</td>
                <td class="code-cell">${passwordDisplay}</td>
                <td>
                    <div>${escapeHTML(item.category)}</div>
                    ${item.url ? `<div style="font-size: 7.5pt; color: #475569;">${escapeHTML(item.url)}</div>` : ''}
                </td>
                <td style="font-size: 8pt;">${escapeHTML(item.notes || '-')}</td>
            </tr>
        `;
    }).join('');

    closeModal('modal-print-options');

    // Dar tiempo mínimo para renderizar el DOM antes de invocar print()
    setTimeout(() => {
        window.print();
    }, 150);
}

/* ==========================================================================
   SECCIÓN 10: RESPALDOS CIFRADOS (Backup & Restore)
   ========================================================================== */

function openBackupModal() {
    document.getElementById('backup-file-input').value = '';
    document.getElementById('import-strategy-box').style.display = 'none';
    state.pendingImportData = null;
    openModal('modal-backup');
}

/**
 * Exporta la base de datos completa como un archivo JSON cifrado con AES-GCM
 */
async function handleExportBackup() {
    if (!state.masterCryptoKey) {
        showToast('La sesión no está autenticada.', 'danger');
        return;
    }

    try {
        const saltBase64 = await getVaultMeta('salt');
        const encryptedRecords = await getAllEncryptedCredentials();
        const settings = await getVaultMeta('settings');

        const backupPayload = {
            format: 'SECURE_CREDENTIAL_VAULT_BACKUP',
            version: 1,
            exportedAt: new Date().toISOString(),
            operator: state.operatorName,
            salt: saltBase64,
            recordsCount: encryptedRecords.length,
            records: encryptedRecords,
            settings: settings
        };

        const jsonString = JSON.stringify(backupPayload, null, 2);
        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        a.href = url;
        a.download = `respaldo_boveda_credenciales_${timestamp}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast(`Respaldo cifrado exportado exitosamente (${encryptedRecords.length} credenciales).`, 'success');
    } catch (err) {
        console.error('Error al exportar respaldo:', err);
        showToast('Error al exportar respaldo: ' + err.message, 'danger');
    }
}

/**
 * Procesa el archivo de respaldo seleccionado
 */
async function handleBackupFileSelected(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const data = JSON.parse(text);

        if (data.format !== 'SECURE_CREDENTIAL_VAULT_BACKUP' || !Array.isArray(data.records)) {
            throw new Error('El archivo seleccionado no corresponde a un respaldo válido de la bóveda.');
        }

        state.pendingImportData = data;
        const box = document.getElementById('import-strategy-box');
        box.style.display = 'block';
        showToast(`Archivo validado: ${data.records.length} credenciales encontradas en el respaldo. Selecciona el modo de restauración.`, 'info');
    } catch (err) {
        console.error('Error al leer archivo de respaldo:', err);
        showToast('Archivo inválido o corrupto: ' + err.message, 'danger');
        event.target.value = '';
        state.pendingImportData = null;
    }
}

/**
 * Ejecuta la importación y restauración de datos
 */
async function handleExecuteImport() {
    if (!state.pendingImportData || !state.masterCryptoKey) {
        showToast('No hay datos de importación listos o la sesión está inactiva.', 'warning');
        return;
    }

    const strategy = document.getElementById('import-strategy').value;
    const records = state.pendingImportData.records;

    try {
        // Validar que al menos un registro se pueda descifrar con la clave actual
        // o advertir si las claves no coinciden
        let decryptableCount = 0;
        for (const r of records) {
            try {
                await decryptPayload(r.encryptedData, state.masterCryptoKey);
                decryptableCount++;
            } catch {
                // Registro cifrado con otra sal/clave
            }
        }

        if (decryptableCount === 0 && records.length > 0) {
            alert('Atención de Seguridad: Las credenciales del archivo de respaldo fueron cifradas con una contraseña maestra distinta a la de tu sesión actual. No se pueden descifrar con la clave maestra actual del Usuario/Operador.');
            return;
        }

        if (strategy === 'replace') {
            await clearAllCredentials();
        }

        for (const record of records) {
            await saveEncryptedCredential(record);
        }

        // Recargar la memoria
        await loadAndDecryptAllCredentials();
        renderCredentialsGrid();
        closeModal('modal-backup');

        showToast(`Restauración completada. Se importaron ${records.length} registros (${decryptableCount} verificados con éxito).`, 'success');
    } catch (err) {
        console.error('Error al ejecutar importación:', err);
        showToast('Error en la importación: ' + err.message, 'danger');
    }
}

/* ==========================================================================
   SECCIÓN 11: CONFIGURACIÓN DE SEGURIDAD Y RESTABLECIMIENTO DE FÁBRICA
   ========================================================================== */

async function openSettingsModal() {
    document.getElementById('settings-operator-name').value = state.operatorName;
    document.getElementById('settings-inactivity-timeout').value = String(state.inactivityMinutes);
    await updateSettingsBiometricsUI();
    openModal('modal-settings');
}

async function updateSettingsBiometricsUI() {
    const statusText = document.getElementById('settings-bio-status-text');
    const toggleBtn = document.getElementById('btn-toggle-biometrics-settings');
    if (!statusText || !toggleBtn) return;

    state.hasBiometricHardware = await isBiometricHardwareAvailable();
    state.isBiometricsActive = await isBiometricsConfigured();

    if (!state.hasBiometricHardware) {
        statusText.textContent = 'Estado: Este equipo o navegador no dispone de lector biométrico compatible.';
        statusText.style.color = 'var(--text-muted)';
        toggleBtn.style.display = 'none';
        return;
    }

    toggleBtn.style.display = 'inline-flex';
    if (state.isBiometricsActive) {
        statusText.textContent = 'Estado: Activo. Puedes ingresar con Touch ID / Windows Hello.';
        statusText.style.color = 'var(--success)';
        toggleBtn.className = 'btn btn-danger-outline';
        toggleBtn.innerHTML = '<span>Desvincular Huella Digital</span>';
    } else {
        statusText.textContent = 'Estado: Inactivo. Puedes vincular tu huella digital para acceso rápido.';
        statusText.style.color = 'var(--text-muted)';
        toggleBtn.className = 'btn btn-secondary';
        toggleBtn.innerHTML = '<span>Vincular Huella Digital en este Equipo</span>';
    }
}

async function handleToggleBiometricsInSettings() {
    if (state.isBiometricsActive) {
        const confirmDisable = window.confirm('¿Deseas desvincular el acceso por huella digital en este equipo? En adelante solo podrás ingresar con tu contraseña maestra.');
        if (!confirmDisable) return;
        await disableBiometrics();
        state.isBiometricsActive = false;
        await updateSettingsBiometricsUI();
        showToast('Huella digital desvinculada exitosamente.', 'info');
    } else {
        const masterPass = window.prompt('Para vincular tu sensor biométrico (Touch ID / Windows Hello), introduce tu Contraseña Maestra de Usuario / Operador:');
        if (!masterPass) return;

        // Validar que la contraseña maestra sea correcta antes de registrar
        const saltBase64 = await getVaultMeta('salt');
        const integrityToken = await getVaultMeta('integrity_token');
        const salt = base64ToBuffer(saltBase64);
        const derivedKey = await deriveMasterKey(masterPass, salt, 100000);
        const isValid = await verifyMasterKey(integrityToken, derivedKey);

        if (!isValid) {
            showToast('Contraseña maestra incorrecta. No se pudo vincular la huella.', 'danger');
            return;
        }

        try {
            await registerBiometricCredential(state.operatorName, masterPass);
            state.isBiometricsActive = true;
            await updateSettingsBiometricsUI();
            showToast('¡Huella digital vinculada exitosamente con este equipo!', 'success');
        } catch (err) {
            console.error('Error al registrar huella:', err);
            showToast('No se pudo registrar la huella: ' + err.message, 'warning');
        }
    }
}

async function handleSettingsSubmit(event) {
    event.preventDefault();
    const newName = document.getElementById('settings-operator-name').value.trim() || 'Usuario / Operador';
    const newTimeout = Number(document.getElementById('settings-inactivity-timeout').value) || 10;

    state.operatorName = newName;
    state.inactivityMinutes = newTimeout;
    state.inactivityRemainingSeconds = newTimeout * 60;

    try {
        const currentSettings = await getVaultMeta('settings') || {};
        currentSettings.operatorName = newName;
        currentSettings.inactivityTimeoutMinutes = newTimeout;
        currentSettings.updatedAt = new Date().toISOString();
        await saveVaultMeta('settings', currentSettings);

        updateOperatorLabelUI();
        updateInactivityDisplay();
        closeModal('modal-settings');
        showToast('Configuración actualizada.', 'success');
    } catch (err) {
        console.error('Error al guardar ajustes:', err);
        showToast('Error al guardar configuración: ' + err.message, 'danger');
    }
}

async function handleEmergencyReset() {
    const confirm1 = window.confirm('¿Deseas restablecer de fábrica el Custodio Local de Credenciales? Esta acción ELIMINARÁ PERMANENTEMENTE todas las credenciales y la base de datos de este dispositivo.');
    if (!confirm1) return;

    const confirm2 = window.prompt('Para confirmar la destrucción irreversible de la bóveda local, escribe la palabra "DESTRUIR":');
    if (confirm2 !== 'DESTRUIR') {
        showToast('Acción cancelada. La bóveda no fue modificada.', 'info');
        return;
    }

    try {
        await destroyVaultDatabase();
        window.location.reload();
    } catch (err) {
        alert('Error al destruir la base de datos: ' + err.message);
    }
}

/* ==========================================================================
   SECCIÓN 12: REGISTRO GLOBAL DE EVENTOS (Event Listeners)
   ========================================================================== */

function setupEventListeners() {
    // 1. Detección de actividad del Usuario/Operador para restablecer inactividad
    const activityEvents = ['mousemove', 'keydown', 'touchstart', 'pointerdown', 'scroll', 'click'];
    activityEvents.forEach(eventName => {
        window.addEventListener(eventName, resetInactivityCountdown, { passive: true });
    });

    // 2. Formularios de Autenticación y Selector Dual (Huella vs Contraseña)
    const onboardingForm = document.getElementById('onboarding-form');
    if (onboardingForm) onboardingForm.addEventListener('submit', handleOnboardingSubmit);

    const unlockForm = document.getElementById('unlock-form');
    if (unlockForm) unlockForm.addEventListener('submit', handleUnlockSubmit);

    // Botón de lectura biométrica
    document.getElementById('btn-trigger-biometrics')?.addEventListener('click', handleBiometricLogin);

    // Pestañas de alternancia dual: Huella Digital <-> Contraseña Maestra
    const tabBiometric = document.getElementById('tab-btn-biometric');
    const tabPassword = document.getElementById('tab-btn-password');
    const bioSection = document.getElementById('unlock-biometric-section');
    const passForm = document.getElementById('unlock-form');

    tabBiometric?.addEventListener('click', () => {
        tabBiometric.classList.add('active');
        tabPassword.classList.remove('active');
        if (bioSection) bioSection.style.display = 'flex';
        if (passForm) passForm.style.display = 'none';
    });

    tabPassword?.addEventListener('click', () => {
        tabPassword.classList.add('active');
        tabBiometric.classList.remove('active');
        if (bioSection) bioSection.style.display = 'none';
        if (passForm) passForm.style.display = 'block';
        document.getElementById('unlock-password')?.focus();
    });

    // Botón de configuración biométrica en ajustes
    document.getElementById('btn-toggle-biometrics-settings')?.addEventListener('click', handleToggleBiometricsInSettings);

    // Medidor de fortaleza para el onboarding
    const initMasterPass = document.getElementById('init-master-password');
    if (initMasterPass) {
        initMasterPass.addEventListener('input', () => {
            updateStrengthMeterUI('init-master-password', 'init-strength-bar', 'init-strength-label', 'init-strength-entropy');
        });
    }

    // 3. Botones de Cabecera y Barra de Herramientas
    document.getElementById('btn-lock-session')?.addEventListener('click', () => lockVaultSession(false));
    document.getElementById('btn-new-credential')?.addEventListener('click', openNewCredentialModal);
    document.getElementById('btn-empty-action')?.addEventListener('click', openNewCredentialModal);
    document.getElementById('btn-open-generator')?.addEventListener('click', openPasswordGeneratorModal);
    document.getElementById('btn-open-print')?.addEventListener('click', openPrintModal);
    document.getElementById('btn-open-backup')?.addEventListener('click', openBackupModal);
    document.getElementById('btn-open-settings')?.addEventListener('click', openSettingsModal);
    document.getElementById('btn-show-emergency-reset')?.addEventListener('click', handleEmergencyReset);
    document.getElementById('btn-danger-reset-vault')?.addEventListener('click', handleEmergencyReset);

    // 4. Búsqueda y Filtros en Tiempo Real
    const searchInput = document.getElementById('search-input');
    const searchClearBtn = document.getElementById('search-clear-btn');

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.trim();
            if (searchClearBtn) {
                if (state.searchQuery.length > 0) {
                    searchClearBtn.classList.add('active');
                } else {
                    searchClearBtn.classList.remove('active');
                }
            }
            renderCredentialsGrid();
        });
    }

    if (searchClearBtn) {
        searchClearBtn.addEventListener('click', () => {
            searchInput.value = '';
            state.searchQuery = '';
            searchClearBtn.classList.remove('active');
            renderCredentialsGrid();
            searchInput.focus();
        });
    }

    // Filtro por píldoras de categorías
    const categoryPills = document.querySelectorAll('.pill-btn');
    categoryPills.forEach(pill => {
        pill.addEventListener('click', () => {
            categoryPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            state.selectedCategory = pill.dataset.category || 'ALL';
            renderCredentialsGrid();
        });
    });

    // 5. CRUD de Credenciales
    const credentialForm = document.getElementById('credential-form');
    if (credentialForm) credentialForm.addEventListener('submit', handleCredentialFormSubmit);

    const credPasswordInput = document.getElementById('cred-password');
    if (credPasswordInput) {
        credPasswordInput.addEventListener('input', () => {
            updateStrengthMeterUI('cred-password', 'cred-strength-bar', 'cred-strength-label', 'cred-strength-entropy');
        });
    }

    // Botón de generación rápida en formulario de credencial
    document.getElementById('btn-quick-generate-password')?.addEventListener('click', () => {
        const generated = generateSecurePassword({ length: 20 });
        if (credPasswordInput) {
            credPasswordInput.value = generated.password;
            credPasswordInput.type = 'text'; // Mostrar momentáneamente
            updateStrengthMeterUI('cred-password', 'cred-strength-bar', 'cred-strength-label', 'cred-strength-entropy');
            showToast('Contraseña de alta entropía generada.', 'info', 2000);
        }
    });

    // 6. Generador de Contraseñas Modal
    document.getElementById('gen-length-range')?.addEventListener('input', (e) => {
        document.getElementById('gen-length-label').textContent = `${e.target.value} caracteres`;
        refreshGeneratedPassword();
    });

    ['gen-opt-uppercase', 'gen-opt-lowercase', 'gen-opt-numbers', 'gen-opt-symbols'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', refreshGeneratedPassword);
    });

    document.getElementById('btn-refresh-generated')?.addEventListener('click', refreshGeneratedPassword);
    
    document.getElementById('btn-copy-generated')?.addEventListener('click', () => {
        const text = document.getElementById('gen-result-display')?.textContent;
        copyToClipboardSafe(text, 'Contraseña');
    });

    document.getElementById('btn-use-generated-password')?.addEventListener('click', () => {
        const text = document.getElementById('gen-result-display')?.textContent;
        const targetInput = document.getElementById('cred-password');
        if (targetInput) {
            targetInput.value = text;
            updateStrengthMeterUI('cred-password', 'cred-strength-bar', 'cred-strength-label', 'cred-strength-entropy');
        }
        closeModal('modal-generator');
        showToast('Contraseña insertada en el formulario.', 'success', 2000);
    });

    // 7. Respaldos
    document.getElementById('btn-export-backup')?.addEventListener('click', handleExportBackup);
    document.getElementById('btn-trigger-file-input')?.addEventListener('click', () => {
        document.getElementById('backup-file-input')?.click();
    });
    document.getElementById('backup-file-input')?.addEventListener('change', handleBackupFileSelected);
    document.getElementById('btn-execute-import')?.addEventListener('click', handleExecuteImport);

    // 8. Ajustes
    document.getElementById('settings-form')?.addEventListener('submit', handleSettingsSubmit);

    // 9. Reportes e Impresión
    document.getElementById('btn-execute-print')?.addEventListener('click', executePrintReport);

    // 10. Delegación de eventos en las tarjetas de credenciales
    const container = document.getElementById('credentials-container');
    if (container) {
        container.addEventListener('click', (e) => {
            const btnCopyUser = e.target.closest('.btn-copy-user');
            if (btnCopyUser) {
                copyToClipboardSafe(btnCopyUser.dataset.user, 'User');
                return;
            }

            const btnCopyPass = e.target.closest('.btn-copy-pass');
            if (btnCopyPass) {
                copyToClipboardSafe(btnCopyPass.dataset.password, 'Contraseña');
                return;
            }

            const btnTogglePass = e.target.closest('.btn-toggle-card-pass');
            if (btnTogglePass) {
                const card = btnTogglePass.closest('.credential-card');
                const passField = card.querySelector('[data-password]');
                if (passField) {
                    if (passField.classList.contains('password-masked')) {
                        passField.textContent = passField.dataset.password;
                        passField.classList.remove('password-masked');
                    } else {
                        passField.textContent = '••••••••••••';
                        passField.classList.add('password-masked');
                    }
                }
                return;
            }

            const btnEdit = e.target.closest('.btn-edit-cred');
            if (btnEdit) {
                openEditCredentialModal(btnEdit.dataset.id);
                return;
            }

            const btnDelete = e.target.closest('.btn-delete-cred');
            if (btnDelete) {
                handleDeleteCredential(btnDelete.dataset.id);
                return;
            }
        });
    }

    // 11. Botones de alternar visibilidad de contraseña (inputs de formularios)
    document.querySelectorAll('.toggle-password-visibility').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.target;
            const input = document.getElementById(targetId);
            if (input) {
                input.type = input.type === 'password' ? 'text' : 'password';
            }
        });
    });

    // 12. Cierre de modales
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', () => closeAllModals());
    });

    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) closeAllModals();
        });
    });

    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeAllModals();
    });
}

/* ==========================================================================
   SECCIÓN 13: UTILIDADES DE INTERFAZ Y MODALES
   ========================================================================== */

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

function closeAllModals() {
    document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('active'));
}

/**
 * Notificación flotante tipo Toast
 * @param {string} message
 * @param {'info'|'success'|'warning'|'danger'} [type='info']
 * @param {number} [duration=3500]
 */
function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        toast.style.transition = 'all 0.25s ease';
        setTimeout(() => toast.remove(), 250);
    }, duration);
}

function formatDate(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    return date.toLocaleDateString('es-ES', {
        day: '2-digit',
        month: 'short',
        year: 'numeric'
    });
}

function escapeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeAttr(str) {
    if (!str) return '';
    return String(str)
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
