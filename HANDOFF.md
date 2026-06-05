# Playground last-mile (only remaining item)

State: extraction DONE (downstream consumer on v0.1.0, verified). Landing page
live. Playground boots fully (Pyodide + vendored wheels via unpackArchive +
ssl loaded, server logs "ready") — but the iframe stays empty: SW->page
message round-trip for app/* requests doesn't complete.

Done already: sw.js routes to the controller page (not iframe client) as of
commit "playground sw: route requests to the controller page". Suspects for
the remaining gap, in order:
1. stale SW: browser kept the old worker — verify with a hard
   unregister (navigator.serviceWorker.getRegistrations -> r.unregister())
   then reload twice; consider a version query (sw.js?v=N) on register()
2. handle() proxy: navigator.serviceWorker message listener calls the PyProxy
   `handle` — confirm it resolves (add console.log of out) and that
   e.ports[0] exists for iframe-originated fetches
3. iframe request mode=navigate may not be interceptable before controller
   claims — first load happens right after register; try reloading the
   iframe after a tick

Debug loop: site/ is static — `python3 -m http.server -d site 8990` and edit
locally (SW scope: serve under /kairos/ path or adjust APP_PREFIX detection),
no CI roundtrips needed.
