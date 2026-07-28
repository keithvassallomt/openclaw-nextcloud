import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = dirname(fileURLToPath(import.meta.url));
const suites = ['regressions.mjs', 'safety-features.mjs'];

for (const suite of suites) {
  const code = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(testDir, suite)], {
      stdio: 'inherit'
    });
    child.once('error', reject);
    child.once('close', resolve);
  });

  if (code !== 0) process.exit(code ?? 1);
}
