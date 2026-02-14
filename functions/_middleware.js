export async function onRequest(context) {
  const url = new URL(context.request.url);
  if (url.hostname === "www.aiwre.io") {
    url.hostname = "aiwre.io";
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }

  const legacyRouteRedirects = {
    "/docs": "/",
    "/docs.html": "/",
    "/docs.md": "/index.md",
    "/design": "/protocol",
    "/design.html": "/protocol",
    "/design.md": "/protocol.md",
    "/spec": "/protocol",
    "/spec.html": "/protocol",
    "/spec.md": "/protocol.md",
    "/deploy": "/",
    "/deploy.html": "/",
    "/deploy.md": "/index.md",
  };

  const redirectTarget = legacyRouteRedirects[url.pathname];
  if (redirectTarget) {
    return Response.redirect(new URL(redirectTarget, url.origin).toString(), 301);
  }

  return context.next();
}
