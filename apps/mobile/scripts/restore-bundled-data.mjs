import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataRoot = path.join(appRoot, 'src', 'data');
const bundleRoot = path.join(dataRoot, 'bundled');

const bundles = [
  { name: 'curriculum.json', target: path.join(dataRoot, 'curriculum.json') },
  { name: 'quizzes.json', target: path.join(dataRoot, 'quizzes.json') },
  { name: 'labs.json', target: path.join(dataRoot, 'labs.json') },
  {
    name: 'jadx-learning-report.json',
    target: path.join(dataRoot, 'samples', 'jadx-learning-report.json'),
  },
];

for (const bundle of bundles) {
  const prefix = `${bundle.name}.gz.b64.part`;
  const parts = fs
    .readdirSync(bundleRoot)
    .filter((entry) => entry.startsWith(prefix))
    .sort((left, right) => {
      const leftIndex = Number(left.slice(prefix.length));
      const rightIndex = Number(right.slice(prefix.length));
      return leftIndex - rightIndex;
    });

  if (parts.length === 0) {
    throw new Error(`missing bundled learning data for ${bundle.name}`);
  }

  const encoded = parts
    .map((entry) => fs.readFileSync(path.join(bundleRoot, entry), 'utf8').trim())
    .join('');
  const decoded = zlib.gunzipSync(Buffer.from(encoded, 'base64'));
  const parsed = JSON.parse(decoded.toString('utf8'));
  const normalized = `${JSON.stringify(parsed)}\n`;

  fs.mkdirSync(path.dirname(bundle.target), { recursive: true });
  fs.writeFileSync(bundle.target, normalized);
  console.log(`restored ${path.relative(appRoot, bundle.target)}`);
}
