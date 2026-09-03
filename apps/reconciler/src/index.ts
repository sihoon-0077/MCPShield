import { reconcileSubmittedOperations } from "../../api/src/reconcile.js";
import { registryClientFromEnv } from "../../api/src/registry-client.js";
import { Repository } from "../../api/src/repository.js";

const registry = registryClientFromEnv();
if (!registry) throw new Error("Reconciler requires EVM configuration");
const repository = new Repository(process.env.DATABASE_PATH ?? "./mcpshield.db");
try {
  console.log(JSON.stringify(await reconcileSubmittedOperations(repository, registry)));
} finally {
  repository.close();
}
