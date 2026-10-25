// KMS release site Worker (6B A5). wrangler.jsonc's run_worker_first sends every
// /ui/* request here first; other paths are plain static files with
// public/_headers, though Cloudflare may also pass some of those through here.
// A version folder's files never change, so a file that was found is kept for a
// year. Anything else (a missing file, a redirect, an error) must never be: a
// browser would keep "not found" after the version is published. Cloudflare does
// not promise _headers on responses that pass through a Worker, so every header
// is set here. The policy is the one in public/_headers (tools/build-web.cjs CSP).
const SECURITY = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://accounts.google.com/gsi/client; style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style; connect-src 'self' https://script.google.com https://script.googleusercontent.com https://accounts.google.com/gsi/; frame-src 'self' https://accounts.google.com/gsi/; img-src 'self' data: blob:; worker-src blob:; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};
// Isolation headers can break Google sign-in's pop-up, so none is ever passed on.
const REMOVED = ['Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy'];
const FOUND = 'public, max-age=31536000, immutable';

export default {
  async fetch(request, env) {
    let asset;
    try {
      asset = await env.ASSETS.fetch(request);
    } catch (e) {
      // A plain answer with the same headers, never Cloudflare's own error page.
      return new Response('Temporarily unavailable', {status: 503,
        headers: {...SECURITY, 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store'}});
    }
    const response = new Response(asset.body, asset);
    Object.entries(SECURITY).forEach(([name, value]) => response.headers.set(name, value));
    REMOVED.forEach(name => response.headers.delete(name));
    // 304 confirms a found file is unchanged; only 200 and 304 are ever cached.
    response.headers.set('Cache-Control', asset.status === 200 || asset.status === 304 ? FOUND : 'no-store');
    return response;
  }
};
