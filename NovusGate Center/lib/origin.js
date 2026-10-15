// sameOrigin reports whether a request comes from the Center's own page (or
// from a client that sends no Origin, such as curl). A page from any other
// site must not reach the API or the SSH terminal through the user's
// browser: the Center has no login of its own.
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  const host = req.headers.host;
  if (!host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false; // "null" and other malformed origins
  }
}

module.exports = { sameOrigin };
