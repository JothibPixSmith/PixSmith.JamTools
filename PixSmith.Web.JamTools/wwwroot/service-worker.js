// In development, always fetch from the network and do not enable offline support.
// This is because caching would make development more difficult (changes would not
// be reflected on the first load after each change).
//
// The production worker is service-worker.published.js — the csproj swaps this file
// for that one at publish time (see the <ServiceWorker> item). Keep caching logic
// there, not here.
self.addEventListener('fetch', () => { });
