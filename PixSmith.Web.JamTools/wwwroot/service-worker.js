// In development, always fetch from the network and do not enable offline support.
// This is because caching would make development more difficult (changes would not
// be reflected on the first load after each change).
self.addEventListener('fetch', () => { });
// =============================================================
// service-worker.js
//
// CACHE_VERSION is replaced by the GitHub Actions workflow with
// the actual build timestamp so every deployment gets a new cache.
// =============================================================

const CACHE_VERSION = '__BUILD_VERSION__';
const CACHE_NAME = `blazor-cache-v${CACHE_VERSION}`;

// Assets to pre-cache on install (update as needed)
const PRECACHE_ASSETS = [
    './',
    './index.html',
    './app.css',
    './build-version.txt',
];

// ---------- Install ----------
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_ASSETS))
    );
    // Don't call skipWaiting() here — we wait for the page to tell us via postMessage
});

// ---------- Activate ----------
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(
                keys
                    .filter(key => key !== CACHE_NAME)
                    .map(key => caches.delete(key))   // delete all OLD caches
            )
        ).then(() => self.clients.claim())
    );
});

// ---------- Fetch ----------
self.addEventListener('fetch', event => {
    // Never cache the version file — always go to network so updates are detected
    if (event.request.url.includes('build-version.txt')) {
        event.respondWith(fetch(event.request));
        return;
    }

    event.respondWith(
        caches.match(event.request).then(cached => {
            if (cached) return cached;
            return fetch(event.request).then(response => {
                // Cache successful GET responses
                if (response && response.status === 200 && event.request.method === 'GET') {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
                }
                return response;
            });
        })
    );
});

// ---------- Skip waiting on demand ----------
self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});
