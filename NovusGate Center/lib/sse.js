// Ends an install/update request after a failure. Once the SSE headers are
// flushed, Express can no longer send a JSON error (it throws
// ERR_HTTP_HEADERS_SENT), so the error goes out as a final stream event.
function endWithError(res, err) {
  const message = err instanceof Error ? err.message : String(err);
  if (res.headersSent) {
    res.write(`data: ${JSON.stringify({ text: `[ERROR] ${message}\n`, stderr: true })}\n\n`);
    res.write(`data: ${JSON.stringify({ done: true, success: false, message })}\n\n`);
    res.end();
    return;
  }
  res.status(500).json({ error: message });
}

module.exports = { endWithError };
