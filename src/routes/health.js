// Health check endpoint for monitoring
export function healthCheck(req, res) {
  res.json({
    status: "ok",
    version: "2.0",
    timestamp: new Date().toISOString(),
    service: "waelto5clean-backend"
  });
}
