// Serves loomseal.com. Both loomseal.com and www.loomseal.com are custom domains on this
// Worker, so the www redirect has to happen here: a Cloudflare redirect rule never sees a
// request that a Worker custom domain already answered.
//
// LoomSeal is retired. Every path that is not a surviving asset returns the retirement
// notice with a 404 so old links to /spec and /faq land somewhere that explains itself
// instead of a bare error.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.startsWith("www.")) {
      url.hostname = url.hostname.slice(4);
      return Response.redirect(url.toString(), 301);
    }

    const response = await env.ASSETS.fetch(request);
    if (response.status !== 404) {
      return response;
    }

    const notice = await env.ASSETS.fetch(new URL("/", url));
    return new Response(notice.body, {
      status: 404,
      headers: notice.headers,
    });
  },
};
