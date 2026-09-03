import { buildApp } from "./app.js";
import { registryClientFromEnv } from "./registry-client.js";

const app = await buildApp({
  databasePath: process.env.DATABASE_PATH ?? "./mcpshield.db",
  validatorAddresses: process.env.VALIDATOR_ADDRESSES?.split(","),
  logger: true,
  registryClient: registryClientFromEnv(),
});

const port = Number(process.env.API_PORT ?? 3001);
await app.listen({ host: process.env.API_HOST ?? "127.0.0.1", port });
