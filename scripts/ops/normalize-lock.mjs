import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';

// npm can rehydrate Ganache's bundled development shrinkwrap into the root lock,
// including non-optional darwin-only fsevents. These entries are explicitly
// extraneous, not application dependencies. Keep Ganache's real dependency pins.
// Upstream: https://github.com/npm/cli/issues/7622
const file = new URL('../../package-lock.json', import.meta.url);
const lock = JSON.parse(readFileSync(file, 'utf8'));
const extra = Object.entries(lock.packages).filter(([, pkg]) => pkg.extraneous);
assert.ok(extra.every(([path]) => path.startsWith('node_modules/ganache/node_modules/')), 'Unexpected extraneous lock entries require review');
if (process.argv.includes('--check')) assert.equal(extra.length, 0, 'Run npm run lock:normalize after dependency updates');
else if (extra.length) {
  for (const [path] of extra) delete lock.packages[path];
  writeFileSync(file, `${JSON.stringify(lock, null, 2)}\n`);
}
console.log(`Ganache extraneous lock entries: ${extra.length}; application dependency pins preserved`);
