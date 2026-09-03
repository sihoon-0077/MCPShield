import { buildApp } from "./app.js";
import { registryClientFromEnv } from "./registry-client.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const registryClient = registryClientFromEnv();
await registryClient?.validateConnection(config.attestationChainId, config.validatorAddresses);

const app = await buildApp({
  databasePath: config.databasePath,
  validatorAddresses: config.validatorAddresses,
  logger: true,
  registryClient,
  adminApiToken: config.adminApiToken,
  scannerApiToken: config.scannerApiToken,
  corsAllowlist: config.corsAllowlist,
  attestationChainId: config.attestationChainId,
  attestationContract: config.attestationContract,
  operationLeaseMs: config.operationLeaseMs,
});

await app.listen({ host: config.apiHost, port: config.apiPort });
