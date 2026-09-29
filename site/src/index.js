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
  // only cross-origin destination the page is permitted to reach.
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.startsWith("www.")) {
      url.hostname = url.hostname.slice(4);
      return Response.redirect(url.toString(), 301);
    }
    const response = await env.ASSETS.fetch(request);
    // The asset response is immutable, so the headers go onto a copy.
    const out = new Response(response.body, response);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      out.headers.set(name, value);
    }
    return out;
  },
};
