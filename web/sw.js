// オフライン対応。
// ネットにつながるときは常に最新のファイルを取りに行き（取れたらキャッシュも更新）、
// つながらないとき（または3秒以内に応答がないとき）だけキャッシュを使う。
const VERSION = 'v3';
const FILES = [
  './', 'index.html', 'style.css', 'app.js', 'pii.js', 'manifest.webmanifest',
  'icons/apple-touch-icon.png', 'icons/icon-192.png', 'icons/icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

function fromCache(req) {
  return caches.match(req, { ignoreSearch: true })
    .then((hit) => hit || (req.mode === 'navigate' ? caches.match('index.html') : undefined));
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;

  const network = fetch(req, { cache: 'no-cache' }).then((res) => {
    if (res.ok) {
      const copy = res.clone();
      caches.open(VERSION).then((c) => c.put(req, copy));
    }
    return res;
  });
  const timeout = new Promise((resolve) => setTimeout(resolve, 3000));

  e.respondWith(
    Promise.race([network, timeout.then(() => fromCache(req).then((hit) => hit || network))])
      .catch(() => fromCache(req))
      .then((res) => res || fromCache(req)),
  );
});
