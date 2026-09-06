const CACHE_NAME = 'digital-techspmi-shell-v1';
const APP_SHELL = [
  '/offline.html',
  '/manifest.webmanifest',
  '/css/dashboard.css',
  '/css/redesign.css',
  '/css/login-v2.css',
  '/css/logdesign_1.css',
  '/modal-layout.js',
  '/pwa.js',
  '/images/university-logo.svg',
  '/images/system-logo.png',
  '/images/pwa/icon-180.png',
  '/images/pwa/icon-192.png',
  '/images/pwa/icon-512.png',
  '/images/pwa/icon-maskable-192.png',
  '/images/pwa/icon-maskable-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;

  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match('/offline.html')));
    return;
  }

  event.respondWith(caches.match(request).then(cached => {
    const network = fetch(request).then(response => {
      if (response.ok) caches.open(CACHE_NAME).then(cache => cache.put(request, response.clone()));
      return response;
    });
    return cached || network;
  }));
});
