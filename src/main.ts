/** Starts the service with the settings from the environment and stops it cleanly on SIGTERM or SIGINT. */
import { ConfigError, settingsFromEnv } from "./config.ts";
import { build } from "./server.ts";

let settings: ReturnType<typeof settingsFromEnv>;
try {
  settings = settingsFromEnv();
} catch (e) {
  if (e instanceof ConfigError) {
    console.error(`venenum: ${e.message}`);
    process.exit(1);
  }
  throw e;
}
const app = build(settings);
if (!settings.keys.size) app.log.warn("VENENUM_HMAC_KEYS is empty: every scan request will be refused");
if (!settings.origins.length) app.log.warn("VENENUM_FETCH_ORIGINS is empty: POST /v1/scan will refuse every url (POST /v1/scan/bytes still works)");
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    app.log.info({ signal }, "stopping");
    app.close().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  });
}
try {
  await app.listen({ host: settings.host, port: settings.port });
} catch (e) {
  app.log.error(e);
  process.exit(1);
}
