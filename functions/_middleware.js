export async function onRequest(context) {
  const url = new URL(context.request.url);
  if (url.hostname === "www.aiwre.io") {
    url.hostname = "aiwre.io";
    url.protocol = "https:";
    return Response.redirect(url.toString(), 301);
  }
  return context.next();
}
