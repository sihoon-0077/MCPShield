import ganache from "ganache";
import { JsonRpcProvider } from "ethers";
import { deployRegistry } from "./deploy.js";

const port = Number(process.env.CHAIN_PORT ?? 8545);
const server = ganache.server({
  wallet: { deterministic: true, totalAccounts: 5 },
  logging: { quiet: true },
  chain: { chainId: 31337 },
});

await server.listen(port);
const accounts = server.provider.getInitialAccounts();
const entries = Object.entries(accounts);
const deployerKey = entries[0][1].secretKey;
const validators = entries.slice(1, 4).map(([address]) => address) as [
  string,
  string,
  string,
];
const contract = await deployRegistry(`http://127.0.0.1:${port}`, deployerKey, validators);
const address = await contract.getAddress();
const provider = new JsonRpcProvider(`http://127.0.0.1:${port}`);

console.log(
  JSON.stringify(
    {
      rpcUrl: `http://127.0.0.1:${port}`,
      chainId: (await provider.getNetwork()).chainId.toString(),
      registryAddress: address,
      localRelayerPrivateKey: deployerKey,
      validatorAddresses: validators,
      localValidatorPrivateKeys: entries.slice(1, 4).map(([, account]) => account.secretKey),
      note: "Demo keys are deterministic and must never be used outside this local chain.",
    },
    null,
    2,
  ),
);
console.log("Local chain is running. Press Ctrl+C to stop.");

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, async () => {
    await server.close();
    process.exit(0);
  });
}
