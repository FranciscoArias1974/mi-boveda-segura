/**
 * ============================================================================
 * ARCHIVO: sw.js
 * SISTEMA: Custodio Local de Credenciales (Secure Vault)
 * DESCRIPCIÓN: Service Worker para funcionamiento 100% offline y soporte PWA
 *              en Android, Windows, macOS e iOS.
 * ============================================================================
 */

const CACHE_NAME = 'custodio-vault-v1';
const ASSETS_TO_CACHE = [
    './',
    './index.html',
    './manifest.json',
    './css/styles.css',
    './js/crypto.js',
    './js/db.js',
    './js/biometrics.js',
    './js/app.js',
    './icons/icon.svg'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS_TO_CACHE);
        }).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            return cachedResponse || fetch(event.request);
        })
    );
});
