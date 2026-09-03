import { patterns } from "./validation.js";

export function loadConfig(env = process.env) {
  const adminApiToken = env.ADMIN_API_TOKEN;
  if (!adminApiToken || adminApiToken.length < 16) {
    throw new Error("ADMIN_API_TOKEN must contain at least 16 characters");
  }
  const corsAllowlist = env.CORS_ALLOWLIST?.split(",").filter(Boolean) ?? [];
  if (corsAllowlist.length === 0) throw new Error("CORS_ALLOWLIST is required");
  for (const origin of corsAllowlist) new URL(origin);

  const validatorAddresses = env.VALIDATOR_ADDRESSES?.split(",") ?? [];
  if (
    validatorAddresses.length !== 3 ||
    new Set(validatorAddresses.map((item) => item.toLowerCase())).size !== 3 ||
    validatorAddresses.some((item) => !patterns.address.test(item))
  ) throw new Error("VALIDATOR_ADDRESSES must contain three unique EVM addresses");

  const attestationChainId = Number(env.ATTESTATION_CHAIN_ID);
  const attestationContract = env.ATTESTATION_CONTRACT ?? env.REGISTRY_ADDRESS;
  if (!Number.isSafeInteger(attestationChainId) || attestationChainId <= 0) {
    throw new Error("ATTESTATION_CHAIN_ID must be a positive integer");
  }
  if (!attestationContract || !patterns.address.test(attestationContract)) {
    throw new Error("ATTESTATION_CONTRACT or REGISTRY_ADDRESS is required");
  }
  if (
    env.REGISTRY_ADDRESS &&
    env.REGISTRY_ADDRESS.toLowerCase() !== attestationContract.toLowerCase()
  ) throw new Error("ATTESTATION_CONTRACT must equal REGISTRY_ADDRESS in EVM mode");

  const evmValues = [env.RPC_URL, env.REGISTRY_ADDRESS, env.RELAYER_PRIVATE_KEY];
  if (evmValues.some(Boolean) && !evmValues.every(Boolean)) {
    throw new Error("RPC_URL, REGISTRY_ADDRESS and RELAYER_PRIVATE_KEY must be set together");
  }

  return {
    adminApiToken,
    corsAllowlist,
    validatorAddresses,
    attestationChainId,
    attestationContract,
    databasePath: env.DATABASE_PATH ?? "./mcpshield.db",
    apiPort: Number(env.API_PORT ?? 3001),
    apiHost: env.API_HOST ?? "127.0.0.1",
  };
}
