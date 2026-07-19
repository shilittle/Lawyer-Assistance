import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const desktopRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = resolve(desktopRoot, "frontend-dist");
const entry = "index.html";
const ignoredPlaceholders = new Set([".gitkeep"]);

function normalizeRelative(path) {
  return path.split(sep).join("/");
}

function listFiles(directory) {
  const files = [];
  for (const name of readdirSync(directory)) {
    const absolute = resolve(directory, name);
    if (statSync(absolute).isDirectory()) {
      files.push(...listFiles(absolute));
    } else {
      files.push(normalizeRelative(relative(distRoot, absolute)));
    }
  }
  return files;
}

function localReference(currentFile, rawReference) {
  const reference = rawReference.trim().replace(/^[`'"]|[`'"]$/g, "");
  if (
    reference.length === 0 ||
    reference.startsWith("#") ||
    /^(?:data|blob|https?|ipc|asset):/i.test(reference)
  ) {
    return null;
  }
  const withoutSuffix = reference.split(/[?#]/, 1)[0];
  // Minified application strings can contain words such as `from` followed by
  // an expression. Only treat literal, Vite-style paths as asset references;
  // computed imports are represented by concrete chunks elsewhere in output.
  if (!/^(?:\.{0,2}\/|\/)?[A-Za-z0-9_@.%~-]+(?:\/[A-Za-z0-9_@.%~-]+)*$/.test(withoutSuffix)) {
    return null;
  }
  const absolute = withoutSuffix.startsWith("/")
    ? resolve(distRoot, `.${withoutSuffix}`)
    : withoutSuffix.startsWith("assets/")
      ? resolve(distRoot, withoutSuffix)
      : resolve(distRoot, dirname(currentFile), withoutSuffix);
  const normalized = normalizeRelative(relative(distRoot, absolute));
  if (normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`frontend asset escapes dist root: ${rawReference}`);
  }
  return normalized;
}

if (!existsSync(resolve(distRoot, entry))) {
  throw new Error(`missing frontend entry: ${resolve(distRoot, entry)}`);
}

const allFiles = new Set(
  listFiles(distRoot).filter((file) => !ignoredPlaceholders.has(file)),
);
const reachable = new Set([entry]);
const queue = [entry];
const textExtensions = /\.(?:html|css|js|mjs|json|svg)$/i;
const referencePatterns = [
  /\b(?:src|href)\s*=\s*["']([^"']+)["']/gi,
  // Keep CSS `url(...)` case-sensitive here. Minified JavaScript commonly
  // contains the unrelated `URL(value)` constructor, which must not be
  // treated as a path to a bundled asset.
  /\burl\(\s*["']?([^"')]+)["']?\s*\)/g,
  /\b(?:import|from)\s*\(?\s*[`"']([^`"']+)[`"']/gi,
  // Lazy chunks can carry their extracted CSS in Vite's generated
  // `__vite__mapDeps` string table rather than an import statement.
  /[`"']((?:\.\.\/|\.\/|\/)?assets\/[A-Za-z0-9_.~-]+-[A-Za-z0-9_-]{8,}\.(?:css|js|mjs|map|svg|png|webp|woff2?))[`"']/gi,
  /\bsourceMappingURL\s*=\s*([^\s*]+)/gi,
];

while (queue.length > 0) {
  const current = queue.shift();
  if (!textExtensions.test(current)) {
    continue;
  }
  const content = readFileSync(resolve(distRoot, current), "utf8");
  for (const pattern of referencePatterns) {
    pattern.lastIndex = 0;
    for (const match of content.matchAll(pattern)) {
      const referenced = localReference(current, match[1]);
      if (!referenced || reachable.has(referenced)) {
        continue;
      }
      if (!allFiles.has(referenced)) {
        throw new Error(`${current} references missing frontend asset: ${referenced}`);
      }
      reachable.add(referenced);
      queue.push(referenced);
    }
  }
}

const stale = [...allFiles].filter((file) => !reachable.has(file)).sort();
if (stale.length > 0) {
  throw new Error(
    `frontend-dist contains ${stale.length} unreachable/stale file(s): ${stale.join(", ")}`,
  );
}

console.log(`Verified frontend-dist closure: ${reachable.size} file(s), no stale assets.`);
