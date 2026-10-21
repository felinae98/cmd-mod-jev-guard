// Instruction-file sweep, adapted from jev-guard src/skills.js (MIT). The cache lives in Command Code's
// per-mod store instead of ~/.jev-guard/scan-cache.json, so a sweep survives restarts without extra files.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  INSTRUCTION_FILE,
  MIN_SCAN_CHARS,
  instructionMessage,
  judgeInstructions,
  scanInstructions,
  thresholds,
} from "./policy.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "out", "logos", "video", ".tmp", "tmp", "worktrees", "vendor_imports", "marketplaces", "repos"]);
const MAX_DEPTH = 7;
const STORE_KEY = "scanCache";
const MAX_ENTRIES = 5000;

export function userRoots(home = homedir()) {
  return [
    ".claude/skills",
    ".claude/plugins",
    ".claude/CLAUDE.md",
    ".codex",
    ".gemini/extensions",
    ".gemini/config",
    ".pi/agent",
    ".cursor",
    ".copilot",
    ".config/opencode",
    ".agents",
    ".commandcode/skills",
    ".commandcode/agents",
  ].map((path) => join(home, path));
}

export function projectRoots(cwd = process.cwd()) {
  return [
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".claude",
    ".cursor",
    ".opencode",
    ".codex",
    ".gemini",
    ".agents",
    ".github/copilot-instructions.md",
    ".github/hooks",
    "skills",
    ".commandcode/skills",
    ".commandcode/agents",
  ].map((path) => join(cwd, path));
}

export function findInstructionFiles(roots) {
  const found = new Set();
  const walk = (path, depth) => {
    let stats;
    try {
      stats = statSync(path);
    } catch {
      return;
    }
    if (stats.isFile()) {
      if (INSTRUCTION_FILE.test(path) || (/\.md$/i.test(path) && depth === 0)) found.add(path);
      return;
    }
    if (!stats.isDirectory() || depth > MAX_DEPTH) return;
    let names;
    try {
      names = readdirSync(path);
    } catch {
      return;
    }
    for (const name of names) if (!SKIP_DIRS.has(name)) walk(join(path, name), depth + 1);
  };
  for (const root of roots) walk(root, 0);
  return [...found].sort();
}

/** Content-hash cache of instruction-file verdicts, persisted in cmd.store (one JSON file per mod). */
export function createScanCache(store, { now = Date.now, debounceMs = 1500 } = {}) {
  let entries = {};
  try {
    const stored = store?.get?.(STORE_KEY);
    if (stored && typeof stored === "object" && !Array.isArray(stored)) entries = stored;
  } catch {
    entries = {};
  }

  let timer;
  const flush = () => {
    timer = undefined;
    try {
      void store?.set?.(STORE_KEY, entries);
    } catch {
      // a store write failure must never break a tool call
    }
  };
  const schedule = () => {
    if (!store?.set || timer) return;
    timer = setTimeout(flush, debounceMs);
    timer.unref?.();
  };

  return {
    get(key) {
      return entries[key];
    },
    put(key, value) {
      entries[key] = { ...value, at: now() };
      const keys = Object.keys(entries);
      if (keys.length > MAX_ENTRIES) {
        const drop = keys
          .sort((a, b) => (entries[a].at ?? 0) - (entries[b].at ?? 0))
          .slice(0, keys.length - MAX_ENTRIES);
        for (const key of drop) delete entries[key];
      }
      schedule();
    },
    size() {
      return Object.keys(entries).length;
    },
    flush,
  };
}

/** Same text is never sent to Jev twice; the verdict is recomputed from the cached answer on read,
 *  so threshold changes apply to old scans. */
export async function scanInstructionsCached({ text, source }, opts = {}, cache) {
  if (!text || text.length < MIN_SCAN_CHARS) return null;
  const t = thresholds(opts.env ?? process.env);
  const key = createHash("sha1").update(text).digest("hex");
  const hit = cache?.get(key);
  if (hit && typeof hit.kind === "string") {
    const flagged = judgeInstructions(hit.kind, hit.p, t);
    return { flagged, kind: hit.kind, p: hit.p, cached: true, message: instructionMessage(flagged, hit.kind, hit.p, source) };
  }
  const result = await scanInstructions({ text, source }, opts);
  if (result && cache) cache.put(key, { kind: result.kind, p: +result.p.toFixed(2) });
  return result ? { ...result, cached: false } : null;
}

/** @returns {Promise<Array<{file: string, flagged: boolean, kind?: string, p?: number, cached: boolean, message?: string, error?: string}>>} */
export async function scanFiles(files, opts = {}, { concurrency = 4, cache } = {}) {
  const results = [];
  const queue = [...files];
  let failures = 0;
  const worker = async () => {
    for (let file = queue.shift(); file; file = queue.shift()) {
      let text;
      try {
        text = readFileSync(file, "utf8");
      } catch (error) {
        results.push({ file, flagged: false, cached: false, error: error.message });
        continue;
      }
      try {
        const result = await scanInstructionsCached({ text, source: file }, opts, cache);
        if (result) results.push({ file, ...result });
      } catch (error) {
        failures += 1;
        results.push({ file, flagged: false, cached: false, error: error.message });
        if (failures >= 2) queue.length = 0; // the backend is down; stop burning calls
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, files.length) }, worker));
  return results.sort((a, b) => a.file.localeCompare(b.file));
}
