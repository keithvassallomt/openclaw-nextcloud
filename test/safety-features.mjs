import http from 'node:http';
import { spawn } from 'node:child_process';
import {
  mkdtempSync,
  rmSync,
  truncateSync,
  writeFileSync
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bundle = join(repoRoot, 'scripts', 'nextcloud.js');
const requests = [];

const server = http.createServer(async (req, res) => {
  let body = '';
  for await (const chunk of req) body += chunk;
  requests.push({
    method: req.method,
    url: req.url,
    headers: req.headers,
    body
  });

  res.statusCode = 200;
  if (req.method === 'POST' &&
      req.url?.startsWith('/ocs/v2.php/apps/files_sharing/api/v1/shares')) {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      ocs: {
        meta: { status: 'ok', statuscode: 100, message: 'OK' },
        data: {
          id: '29',
          share_type: 3,
          permissions: 1,
          token: 'test-token',
          url: 'https://cloud.example.test/s/test-token'
        }
      }
    }));
  } else if (req.url?.startsWith('/ocs/v2.php/apps/deck/api/v1.0/cards/')) {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      ocs: {
        meta: { status: 'ok', statuscode: 200, message: 'OK' },
        data: []
      }
    }));
  } else if (req.url?.startsWith('/index.php/apps/notes/api/v1/notes/')) {
    res.setHeader('content-type', 'application/json');
    res.end('{}');
  } else {
    res.setHeader('content-type', 'text/plain');
    res.end('ok');
  }
});

await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
const { port } = server.address();
const env = {
  ...process.env,
  NEXTCLOUD_URL: `http://127.0.0.1:${port}`,
  NEXTCLOUD_USER: 'tester',
  NEXTCLOUD_TOKEN: 'dummy-test-token'
};

function run(args) {
  return new Promise(resolveRun => {
    const child = spawn(process.execPath, [bundle, ...args], { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => stdout += chunk);
    child.stderr.on('data', chunk => stderr += chunk);
    child.on('close', code => resolveRun({ args, code, stdout, stderr }));
  });
}

const tests = [];
function record(name, passed, details = {}) {
  tests.push({ name, passed, ...details });
}

const tempDir = mkdtempSync(join(repoRoot, '.test-tmp-'));

const guardedActions = [
  ['notes', 'delete'],
  ['files', 'delete'],
  ['calendar', 'delete'],
  ['tasks', 'delete'],
  ['shares', 'create-link'],
  ['shares', 'delete'],
  ['contacts', 'delete'],
  ['boards', 'delete'],
  ['stacks', 'delete'],
  ['cards', 'delete'],
  ['labels', 'delete']
];

let before;
let result;
try {
for (const [command, subCommand] of guardedActions) {
  before = requests.length;
  result = await run([command, subCommand]);
  record(
    `${command}:${subCommand} requires action-specific confirmation`,
    result.code !== 0 &&
      result.stderr.includes(`Refusing ${command} ${subCommand}`) &&
      result.stderr.includes('See SKILL.md for confirmation requirements') &&
      !result.stderr.includes(`--confirm ${command}:${subCommand}`) &&
      requests.length === before,
    { result }
  );
}

before = requests.length;
result = await run([
  'notes', 'delete', '--id', '123',
  '--confirm', 'files:delete'
]);
record(
  'a confirmation token for another action is rejected',
  result.code !== 0 &&
    result.stderr.includes('Refusing notes delete') &&
    !result.stderr.includes('--confirm notes:delete') &&
    requests.length === before,
  { result }
);

before = requests.length;
result = await run([
  'notes', 'delete', '--id', '123',
  '--confirm', 'notes:delete'
]);
record(
  'matching confirmation preserves legitimate destructive operation',
  result.code === 0 &&
    requests.length === before + 1 &&
    requests.at(-1)?.method === 'DELETE',
  { request: requests.at(-1), result }
);

const passwordFile = join(tempDir, 'share-password');
writeFileSync(passwordFile, 'Secret&Value\n', { mode: 0o600 });

before = requests.length;
result = await run([
  'shares', 'create-link',
  '--path', '/Documents/Reports',
  '--password-file', passwordFile,
  '--confirm', 'shares:create-link'
]);
const sharePost = requests.slice(before).find(entry => entry.method === 'POST');
record(
  'share passwords can be read from a file without entering argv',
  result.code === 0 &&
    sharePost?.body.includes('password=Secret%26Value') &&
    !result.stdout.includes('Secret&Value') &&
    !result.stderr.includes('Secret&Value'),
  { request: sharePost, result }
);

before = requests.length;
result = await run([
  'shares', 'create-link',
  '--path', '/Documents/Reports',
  '--password', 'inline-secret',
  '--password-file', passwordFile,
  '--confirm', 'shares:create-link'
]);
record(
  'inline and file-backed values cannot be supplied together',
  result.code !== 0 &&
    result.stderr.includes('Use either --password or --password-file') &&
    requests.length === before,
  { result }
);

before = requests.length;
result = await run([
  'files', 'upload',
  '--path', 'Documents/private.txt',
  '--content-file', passwordFile
]);
const filePut = requests.slice(before).find(entry =>
  entry.method === 'PUT' &&
  entry.url === '/remote.php/dav/files/tester/Documents/private.txt'
);
record(
  'private text can be read from a file without entering argv',
  result.code === 0 &&
    filePut?.body === 'Secret&Value\n' &&
    !result.stdout.includes('Secret&Value') &&
    !result.stderr.includes('Secret&Value'),
  { request: filePut, result }
);

before = requests.length;
result = await run([
  'notes', 'create',
  '--title', 'Frontmatter',
  '--content', '---\ntitle: example\n---'
]);
record(
  'inline text beginning with dashes is accepted as the flag value',
  result.code === 0 &&
    requests.length === before + 1 &&
    requests.at(-1)?.body.includes('---\\ntitle: example'),
  { request: requests.at(-1), result }
);

before = requests.length;
result = await run([
  'notes', 'edit',
  '--id', '123',
  '--title', 'Allowed edit',
  '--confirm', 'notes:edit'
]);
record(
  'confirmation tokens do not make unguarded actions fail',
  result.code === 0 &&
    requests.length === before + 1,
  { request: requests.at(-1), result }
);

const emptyFile = join(tempDir, 'empty');
writeFileSync(emptyFile, '');
before = requests.length;
result = await run([
  'notes', 'create',
  '--title', 'Empty input',
  '--content-file', emptyFile
]);
record(
  'empty files do not satisfy required text input',
  result.code !== 0 &&
    result.stderr.includes('--content-file must not be empty') &&
    requests.length === before,
  { result }
);

const missingFile = join(tempDir, 'does-not-exist');
before = requests.length;
result = await run([
  'notes', 'create',
  '--title', 'Missing input',
  '--content-file', missingFile
]);
record(
  'missing input files produce a clean CLI error',
  result.code !== 0 &&
    result.stderr.includes('--content-file file not found') &&
    !result.stderr.includes('ENOENT') &&
    requests.length === before,
  { result }
);

const oversizedFile = join(tempDir, 'oversized');
writeFileSync(oversizedFile, '');
truncateSync(oversizedFile, 64 * 1024 * 1024 + 1);
before = requests.length;
result = await run([
  'notes', 'create',
  '--title', 'Oversized input',
  '--content-file', oversizedFile
]);
record(
  'oversized text input is rejected before it is read',
  result.code !== 0 &&
    result.stderr.includes('exceeds the 67108864-byte safety limit') &&
    requests.length === before,
  { result }
);

// Nextcloud's Deck API answers 403 to a DELETE that arrives without a JSON
// content type, so these four requests must carry the same headers as the
// POST/PUT methods beside them rather than the bare listing headers.
const deckDeletes = [
  {
    name: 'boards delete',
    args: ['boards', 'delete', '--board', '1', '--confirm', 'boards:delete'],
    url: '/index.php/apps/deck/api/v1.1/boards/1'
  },
  {
    name: 'stacks delete',
    args: ['stacks', 'delete', '--board', '1', '--stack', '2',
           '--confirm', 'stacks:delete'],
    url: '/index.php/apps/deck/api/v1.1/boards/1/stacks/2'
  },
  {
    name: 'cards delete',
    args: ['cards', 'delete', '--board', '1', '--stack', '2', '--card', '3',
           '--confirm', 'cards:delete'],
    url: '/index.php/apps/deck/api/v1.1/boards/1/stacks/2/cards/3'
  },
  {
    name: 'labels delete',
    args: ['labels', 'delete', '--board', '1', '--label', '4',
           '--confirm', 'labels:delete'],
    url: '/index.php/apps/deck/api/v1.1/boards/1/labels/4'
  },
  {
    // Comments answer on the OCS base rather than the Deck one, so they are
    // covered separately to catch the header drifting back on that path alone.
    name: 'cards comment-delete',
    args: ['cards', 'comment-delete', '--card', '5', '--comment', '6'],
    url: '/ocs/v2.php/apps/deck/api/v1.0/cards/5/comments/6'
  }
];

for (const deckDelete of deckDeletes) {
  before = requests.length;
  result = await run(deckDelete.args);
  const sent = requests.slice(before).find(entry => entry.method === 'DELETE');
  record(
    `${deckDelete.name} sends a JSON content type`,
    result.code === 0 &&
      sent?.url === deckDelete.url &&
      sent?.headers['content-type'] === 'application/json' &&
      sent?.headers['ocs-apirequest'] === 'true',
    { request: sent, result }
  );
}
} finally {
  rmSync(tempDir, { recursive: true, force: true });
  await new Promise(resolveClose => server.close(resolveClose));
}

for (const test of tests) {
  console.log(`${test.passed ? 'PASS' : 'FAIL'} ${test.name}`);
  if (!test.passed) {
    const diagnostic = { ...test };
    delete diagnostic.name;
    delete diagnostic.passed;
    console.log(JSON.stringify(diagnostic, null, 2));
  }
}

const passed = tests.filter(test => test.passed).length;
console.log(`\n${passed}/${tests.length} tests passed`);
process.exit(passed === tests.length ? 0 : 1);
