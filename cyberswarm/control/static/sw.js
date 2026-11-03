// Service worker: cacheia só o shell estático. /api/ NUNCA é cacheada.
const C = "cs-control-v2", SHELL = ["/", "/app.js", "/style.css", "/manifest.json",
  "/icon-192.png", "/icon-512.png", "/icon-maskable-512.png", "/sw.js"];
self.addEventListener("install", e => e.waitUntil(caches.open(C).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener("activate", e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== C).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin || u.pathname.startsWith("/api/")) return;
  e.respondWith(fetch(e.request).then(r => { const cp = r.clone(); caches.open(C).then(c => c.put(e.request, cp)); return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match("/").then(x => x || new Response("offline", {status:503})))));
});
self.addEventListener("message", e => { if (e.data === "ping") e.source && e.source.postMessage("pong"); });
