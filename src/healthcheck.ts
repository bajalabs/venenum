/** The container health check: GET /health on the local port (clamd reachable, signatures fresh). Exit 0 when healthy. */
const port = Number(process.env.PORT ?? 3330);
fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(5_000) }).then(
  (r) => process.exit(r.ok ? 0 : 1),
  () => process.exit(1),
);
