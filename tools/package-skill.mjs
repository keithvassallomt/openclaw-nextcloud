#!/usr/bin/env node

// Assembles just the files ClawHub needs for a skill submission into a folder
// of their own, leaving behind the repo scaffolding — tests, CI, flake, git
// metadata, node_modules. Run it with `npm run package`.
//
//   npm run package                          -> ~/Downloads/openclaw-nextcloud
//   npm run package -- --out /tmp            -> /tmp/openclaw-nextcloud
//   npm run package -- --force               -> replace an existing folder
//   npm run package -- --skip-verify         -> skip the bundle freshness check
//
// This is developer tooling rather than part of the skill's command surface, so
// it prints human-readable progress instead of the CLI's machine-readable JSON.

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat
} from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Everything needed to install and run the skill, and nothing else. The bundle
// carries its own dependencies, so no node_modules and no source beyond
// index.js — which ships so the bundle can be reproduced and audited.
const SUBMISSION_FILES = [
  'SKILL.md',
  'README.md',
  'index.js',
  'package.json',
  'package-lock.json',
  'scripts/nextcloud.js'
];

function fail(message) {
  console.error(`\n✗ ${message}\n`);
  process.exit(1);
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function flagValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    fail(`${name} requires a directory path.`);
  }
  return value;
}

// scripts/nextcloud.js is a build artifact that is also the file agents run, so
// it can drift from index.js without anything failing until much later. CI
// catches that on push; catching it here keeps a stale bundle out of a
// submission in the first place.
async function verifyBundleIsCurrent(pkg) {
  const buildScript = pkg.scripts?.build;
  if (!buildScript || !/--outfile=\S+/.test(buildScript)) {
    console.warn('  ! could not read the build script — skipping freshness check');
    return;
  }

  const scratch = await mkdtemp(join(tmpdir(), 'openclaw-skill-'));
  const freshBundle = join(scratch, 'fresh.js');
  try {
    // Reuse the real build command so the flags cannot drift apart, pointing it
    // at a throwaway outfile. node_modules/.bin joins PATH the way `npm run`
    // would, since the script calls esbuild by bare name.
    const command = buildScript.replace(/--outfile=\S+/, `--outfile="${freshBundle}"`);
    const built = spawnSync(command, {
      cwd: repoRoot,
      shell: true,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${join(repoRoot, 'node_modules', '.bin')}:${process.env.PATH}`
      }
    });

    if (built.status !== 0) {
      console.warn(
        '  ! could not rebuild (is esbuild installed? try `npm ci --ignore-scripts`)' +
        ' — skipping freshness check'
      );
      return;
    }

    const [fresh, committed] = await Promise.all([
      readFile(freshBundle),
      readFile(join(repoRoot, 'scripts', 'nextcloud.js'))
    ]);

    if (!fresh.equals(committed)) {
      fail(
        'scripts/nextcloud.js does not match a fresh build of index.js.\n' +
        '  Packaging it now would submit a bundle that differs from its source.\n' +
        '  Run `npm run build` and commit both files, then try again.\n' +
        '  To package anyway, pass --skip-verify.'
      );
    }
    console.log('  ✓ bundle matches a fresh build of index.js');
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

const pkg = JSON.parse(await readFile(join(repoRoot, 'package.json'), 'utf8'));

const outParent = resolve(flagValue('--out') ?? join(homedir(), 'Downloads'));
const target = join(outParent, pkg.name);

// --force deletes the target, so make sure it can only ever be the named
// subfolder and never the parent, the repo, or a path containing the repo.
if (target === outParent) fail('Refusing to use the destination root as the output folder.');
if (target === repoRoot || repoRoot.startsWith(`${target}/`)) {
  fail(`Refusing to write to ${target} — it is or contains this repository.`);
}

console.log(`\nPackaging ${pkg.name} ${pkg.version} for submission\n`);

const missing = SUBMISSION_FILES.filter(rel => !existsSync(join(repoRoot, rel)));
if (missing.length > 0) {
  fail(`Missing required file(s): ${missing.join(', ')}`);
}

if (hasFlag('--skip-verify')) {
  console.log('  ! skipping bundle freshness check (--skip-verify)');
} else {
  await verifyBundleIsCurrent(pkg);
}

if (existsSync(target)) {
  if (!hasFlag('--force')) {
    fail(`${target} already exists. Remove it, or pass --force to replace it.`);
  }
  await rm(target, { recursive: true, force: true });
  console.log(`  ✓ replaced existing ${relative(homedir(), target) || target}`);
}

let totalBytes = 0;
for (const rel of SUBMISSION_FILES) {
  const from = join(repoRoot, rel);
  const to = join(target, rel);
  await mkdir(dirname(to), { recursive: true });
  await copyFile(from, to);

  // Preserve the executable bit on the bundle — it carries a shebang and is
  // named in package.json's bin field.
  const source = await stat(from);
  await chmod(to, source.mode & 0o777);
  totalBytes += source.size;

  const kb = (source.size / 1024).toFixed(1).padStart(8);
  console.log(`  ${kb} KB  ${rel}`);
}

console.log(
  `\n✓ ${SUBMISSION_FILES.length} files (${(totalBytes / 1024).toFixed(1)} KB) written to\n  ${target}\n`
);
