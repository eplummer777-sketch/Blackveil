self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

function sameOriginPath(raw) {
  try {
    const u = new URL(raw || '/', self.location.origin);
    return u.origin === self.location.origin ? u.pathname + u.search : '/';
  } catch {
    return '/';
  }
}

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = {}; }
  const title = typeof data.title === 'string' && data.title ? data.title.slice(0, 120) : 'Blackveil Security';
  const body = typeof data.body === 'string' && data.body ? data.body.slice(0, 240) : 'Open Blackveil to review a new security alert.';
  const tag = typeof data.tag === 'string' && data.tag ? data.tag.slice(0, 64) : 'blackveil';
  event.waitUntil((async () => {
    await self.registration.showNotification(title, {
      body, tag, renotify: true, icon: '/icon-192.png', badge: '/icon-192.png', data: { url: sameOriginPath(data.url) },
    });
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    windows.forEach((c) => c.postMessage({ type: 'blackveil-push-received', id: typeof data.id === 'string' ? data.id : null }));
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = sameOriginPath(event.notification.data && event.notification.data.url);
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of windows) {
      if (new URL(c.url).origin === self.location.origin && 'focus' in c) {
        c.postMessage({ type: 'blackveil-open', url });
        return c.focus();
      }
    }
    return self.clients.openWindow(url);
  })());
});
