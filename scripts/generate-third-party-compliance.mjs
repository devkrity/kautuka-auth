#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = Object.fromEntries(process.argv.slice(2).reduce((all, value, index, values) => {
  if (value.startsWith('--')) all.push([value.slice(2), values[index + 1]]);
  return all;
}, []));
if (!args['output-dir']) {
  console.error('Usage: node scripts/generate-third-party-compliance.mjs --output-dir <dir>');
  process.exit(2);
}

const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const lockBytes = await readFile(path.join(root, 'package-lock.json'));
const lock = JSON.parse(lockBytes.toString('utf8'));
const catalog = JSON.parse(await readFile(path.join(root, 'compliance/third-party-components.json'), 'utf8'));
const runtimeDependencies = {
  ...(packageJson.dependencies ?? {}),
  ...(packageJson.optionalDependencies ?? {}),
  ...(packageJson.peerDependencies ?? {}),
};
if (Object.keys(runtimeDependencies).length !== 0 && catalog.components.length === 0) {
  throw new Error('Runtime npm dependencies were added. Record each direct dependency, exact resolved version, source and license in compliance/third-party-components.json before generating release compliance.');
}
for (const [name, requested] of Object.entries(runtimeDependencies)) {
  if (!catalog.components.some((component) => component.npmPackage === name && component.requestedVersion === requested)) {
    throw new Error(`Runtime dependency ${name}@${requested} is missing reviewed evidence in compliance/third-party-components.json.`);
  }
}

const output = path.resolve(args['output-dir']);
await mkdir(output, { recursive: true });
const inventory = {
  schemaVersion: 1,
  application: packageJson.name,
  applicationLicense: packageJson.license,
  packageLockSha256: createHash('sha256').update(lockBytes).digest('hex'),
  runtimeDependencies: Object.entries(runtimeDependencies).map(([name, requestedVersion]) => ({
    name,
    requestedVersion,
    reviewedComponent: catalog.components.find((component) => component.npmPackage === name) ?? null,
  })),
  buildTooling: Object.entries(packageJson.devDependencies ?? {}).map(([name, requestedVersion]) => ({
    name,
    requestedVersion,
    resolvedVersion: lock.packages[`node_modules/${name}`]?.version ?? null,
  })),
  components: catalog.components,
};
await writeFile(path.join(output, 'THIRD_PARTY_COMPONENTS.json'), `${JSON.stringify(inventory, null, 2)}\n`);

const notices = [
  `kautuka-auth - Third-party software notices`,
  '',
  'The deployed Worker currently has no third-party npm runtime dependencies. Its application source is licensed under Apache-2.0; see LICENSE.',
  'Cloudflare Workers APIs and the repository-local DpopState Durable Object are platform APIs and first-party source, respectively.',
  'Wrangler and its locked transitive packages are development/build tooling. They are recorded in the attached build-dependencies SBOM and are not bundled into the deployed Worker.',
  'If a third-party runtime dependency is introduced, update the reviewed component catalog and ensure applicable notices and license texts are published with the Worker release.',
  '',
];
await writeFile(path.join(output, 'THIRD_PARTY_NOTICES.txt'), notices.join('\n'));
