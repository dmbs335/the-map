import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(appDir, '../..');
const outputPath = path.join(appDir, 'src/data/generated/catalog.json');
const categoryPattern = /^(0[1-9]|1[0-3])-/;

const categoryNames = {
  '01-injection': 'Injection',
  '02-auth': 'Authentication & Authorization',
  '03-http-protocol': 'HTTP & Protocol',
  '04-server-side': 'Server-Side',
  '05-client-side': 'Client-Side & UI',
  '06-encoding-parser': 'Encoding & Parser',
  '07-application-logic': 'Application Logic',
  '08-infrastructure': 'Infrastructure & Supply Chain',
  '09-frameworks-and-languages': 'Frameworks & Languages',
  '10-recon-methodology': 'Recon & Methodology',
  '11-researchers': 'Security Researchers',
  '12-product-security': 'Product Security',
  '13-misc': 'Miscellaneous & Emerging',
};

async function walk(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(absolute)));
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      files.push(absolute);
    }
  }
  return files;
}

function cleanMarkdown(value) {
  return value
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1')
    .replace(/[*_~>#]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function firstTitle(markdown, fallback) {
  const match = markdown.match(/^#\s+(.+)$/m);
  return cleanMarkdown(match?.[1] ?? fallback);
}

function firstSummary(markdown) {
  const lines = markdown.split(/\r?\n/);
  let inFence = false;
  const paragraph = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('```')) {
      inFence = !inFence;
      continue;
    }
    if (inFence || !line) {
      if (paragraph.length > 0) {
        break;
      }
      continue;
    }
    if (
      line.startsWith('#') ||
      line.startsWith('|') ||
      line.startsWith('- ') ||
      /^\d+\.\s/.test(line) ||
      line.startsWith('>') ||
      line.startsWith('<')
    ) {
      continue;
    }
    paragraph.push(line);
    if (paragraph.join(' ').length >= 220) {
      break;
    }
  }
  const summary = cleanMarkdown(paragraph.join(' '));
  return summary.length > 280 ? `${summary.slice(0, 277)}…` : summary;
}

function tagsFor(relativePath, markdown) {
  const filename = path.basename(relativePath, '.md');
  const headingTags = [...markdown.matchAll(/^##\s+(.+)$/gm)]
    .slice(0, 4)
    .map((match) => cleanMarkdown(match[1]).toLocaleLowerCase())
    .filter(Boolean);
  const pathTags = filename
    .split(/[-_]/)
    .map((item) => item.toLocaleLowerCase())
    .filter((item) => item.length > 2);
  return [...new Set([...pathTags, ...headingTags])].slice(0, 8);
}

function sourceUrl(relativePath) {
  const encoded = relativePath
    .split(path.sep)
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  return `https://github.com/dmbs335/the-map/blob/main/${encoded}`;
}

async function verifiedPaths() {
  const verifiedFile = path.join(repoRoot, 'VERIFIED_ONLY.md');
  try {
    const markdown = await fs.readFile(verifiedFile, 'utf8');
    return new Set(
      [...markdown.matchAll(/\(([^)]+\.md)(?:#[^)]+)?\)/g)]
        .map((match) => decodeURIComponent(match[1]))
        .map((item) => item.replace(/^\.\//, '').replaceAll('\\', '/')),
    );
  } catch {
    return new Set();
  }
}

async function main() {
  const entries = await fs.readdir(repoRoot, { withFileTypes: true });
  const categoryDirs = entries
    .filter((entry) => entry.isDirectory() && categoryPattern.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  if (categoryDirs.length < 13) {
    throw new Error(`Expected at least 13 The Map categories, found ${categoryDirs.length}`);
  }

  const verified = await verifiedPaths();
  const topics = [];
  const categories = [];

  for (const categoryId of categoryDirs) {
    const directory = path.join(repoRoot, categoryId);
    const markdownFiles = (await walk(directory)).sort();
    categories.push({
      id: categoryId,
      title: categoryNames[categoryId] ?? categoryId,
      topicCount: markdownFiles.length,
    });

    for (const absolutePath of markdownFiles) {
      const relativePath = path.relative(repoRoot, absolutePath).replaceAll('\\', '/');
      const markdown = await fs.readFile(absolutePath, 'utf8');
      const fallback = path
        .basename(relativePath, '.md')
        .split('-')
        .map((item) => item.charAt(0).toUpperCase() + item.slice(1))
        .join(' ');
      topics.push({
        id: relativePath.replace(/\.md$/, '').replaceAll('/', ':'),
        title: firstTitle(markdown, fallback),
        categoryId,
        categoryTitle: categoryNames[categoryId] ?? categoryId,
        path: relativePath,
        summary: firstSummary(markdown) || `The Map reference: ${fallback}`,
        tags: tagsFor(relativePath, markdown),
        sourceUrl: sourceUrl(relativePath),
        verified: verified.has(relativePath),
      });
    }
  }

  topics.sort((left, right) =>
    left.categoryId.localeCompare(right.categoryId) ||
    left.title.localeCompare(right.title),
  );
  const catalog = {
    schema: 'the-map.catalog.v1',
    sourceRevision: process.env.GITHUB_SHA ?? 'working-tree',
    categories,
    topics,
    stats: {
      topicCount: topics.length,
      categoryCount: categories.length,
      verifiedCount: topics.filter((topic) => topic.verified).length,
    },
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(catalog, null, 2)}\n`, 'utf8');
  console.log(JSON.stringify(catalog.stats));
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
