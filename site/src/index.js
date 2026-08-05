// Serves loomseal.com. Both loomseal.com and www.loomseal.com are custom domains on this
// Worker, so the www redirect has to happen here: a Cloudflare redirect rule never sees a
// request that a Worker custom domain already answered.
//
// Security headers are applied here rather than in a _headers file, which Cloudflare only honors
// for Pages. A Worker serving assets sends exactly what this code sends, so a site about proving
// things was shipping no security headers at all until they were added here.
const SECURITY_HEADERS = {
  // A year of HTTPS-only, which is safe because both custom domains are HTTPS and always have been.
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  // The page carries one inline script and one inline style block, so those need to be allowed by
  // hash or by keyword. The rest is locked to this origin, and the signup form's endpoint is the
  // only cross-origin destination the page is permitted to reach. The browser verifier compiles
  // WebAssembly, which needs 'wasm-unsafe-eval'; that keyword permits WebAssembly only and does
  // not allow general eval, so the page cannot compile arbitrary scripts.
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self' https://signup.kordloom.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; "),
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

// SKIP_COUNTING matches the static files a page pulls in on its own. Counting them would bury
// the page and download numbers under favicon and image traffic.
const SKIP_COUNTING = /\.(png|ico|svg|css|js|wasm|xml|txt|webmanifest)$/i;

// record writes one row per page view or file download so a launch can be read afterward: how
// many people arrived, how many took the bundle, and which link sent them. It stores the path
// and the referring site and nothing else. No address, no user agent, no cookie, no client
// script, which is the only kind of measurement a site about proof has any business running.
// Measurement never blocks a response, so a counting failure cannot take the site down.
function record(request, url, env) {
  if (!env.SITE_EVENTS || request.method !== "GET") return;
  if (SKIP_COUNTING.test(url.pathname)) return;
  let from = "direct";
  try {
    const referer = request.headers.get("referer");
    if (referer) {
      const host = new URL(referer).hostname;
      if (host !== url.hostname) from = host;
      else return; // A click from one page of this site to another is not an arrival.
    }
  } catch {
    from = "unparsed";
  }
  try {
    env.SITE_EVENTS.writeDataPoint({
      blobs: [url.pathname, from],
      doubles: [1],
      indexes: [url.pathname.slice(0, 32)],
    });
  } catch {
    // Counting is never worth a failed request.
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.startsWith("www.")) {
      url.hostname = url.hostname.slice(4);
      return Response.redirect(url.toString(), 301);
    }
    record(request, url, env);
    const response = await env.ASSETS.fetch(request);
    // The asset response is immutable, so the headers go onto a copy.
    const out = new Response(response.body, response);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      out.headers.set(name, value);
    }
    return out;
  },
};
