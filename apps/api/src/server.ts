import { buildApp } from "./app.js";
import { registryClientFromEnv } from "./registry-client.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const registryClient = registryClientFromEnv();
await registryClient?.validateConnection(config.attestationChainId);

const app = await buildApp({
  databasePath: config.databasePath,
  validatorAddresses: config.validatorAddresses,
  logger: true,
  registryClient,
  adminApiToken: config.adminApiToken,
  corsAllowlist: config.corsAllowlist,
  attestationChainId: config.attestationChainId,
  attestationContract: config.attestationContract,
});

await app.listen({ host: config.apiHost, port: config.apiPort });
