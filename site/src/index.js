// Serves loomseal.com. Both loomseal.com and www.loomseal.com are custom domains on this
// Worker, so the www redirect has to happen here: a Cloudflare redirect rule never sees a
// request that a Worker custom domain already answered.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname.startsWith("www.")) {
      url.hostname = url.hostname.slice(4);
      return Response.redirect(url.toString(), 301);
    }
    return env.ASSETS.fetch(request);
  },
};
