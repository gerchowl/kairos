/* Service worker: routes app/* requests to the in-page Pyodide ASGI server. */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const i = url.pathname.indexOf("/playground/app");
  if (i === -1) return;
  event.respondWith(viaClient(event, url));
});
async function viaClient(event, url) {
  // Always target the controller page (it holds Pyodide) — event.clientId
  // would be the iframe itself, which has no message listener.
  const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  const client = all.find((c) => c.url.includes("/playground/") && !c.url.includes("/playground/app"))
    || all[0];
  if (!client) return new Response("Open the playground page first.", { status: 503 });
  let body = null;
  if (!["GET", "HEAD"].includes(event.request.method)) {
    const buf = new Uint8Array(await event.request.arrayBuffer());
    body = btoa(String.fromCharCode(...buf));
  }
  const headers = {};
  event.request.headers.forEach((v, k) => (headers[k] = v));
  const resp = await new Promise((resolve) => {
    const ch = new MessageChannel();
    ch.port1.onmessage = (e) => resolve(e.data);
    client.postMessage({ method: event.request.method, path: url.pathname,
                         query: url.search.slice(1), headers, body }, [ch.port2]);
  });
  const bytes = Uint8Array.from(atob(resp.body), (c) => c.charCodeAt(0));
  const h = new Headers(resp.headers.filter(([k]) => !/^(content-length|set-cookie)$/i.test(k)));
  return new Response(bytes, { status: resp.status, headers: h });
}
