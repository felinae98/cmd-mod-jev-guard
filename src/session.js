import { createHash } from "node:crypto";

const CAPS = { prompts: 6, intents: 3, calls: 12, flags: 10 };
const MAX_TEXT = 700;

const clip = (text) => (text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}…` : text);
const dedupe = (items) => items.filter((item, index) => item && items.indexOf(item) === index);

/** In-process session memory: the user's words, the agent's intent, recent decisions and flagged content.
 *  A mod lives for the whole session, so no on-disk session files are needed (unlike the hook adapters). */
export function createSession({ decisionTtl = 60_000, permissionTtl = 60_000, maxDecisions = 200 } = {}) {
  const state = { prompts: [], intents: [], calls: [], flags: [], revision: 0 };
  const decisions = new Map();
  const asked = new Map();
  const now = () => Date.now();
  const stamp = (item) => ({ ...item, at: now() });

  return {
    reset() {
      state.prompts = [];
      state.intents = [];
      state.calls = [];
      state.flags = [];
      state.revision++;
      decisions.clear();
      asked.clear();
    },

    get revision() {
      return state.revision;
    },

    addPrompt(text) {
      const value = clip(String(text ?? "").trim());
      if (!value) return;
      state.prompts = [...state.prompts, stamp({ text: value })].slice(-CAPS.prompts);
      state.revision++;
      decisions.clear();
    },

    addIntent(text) {
      const value = clip(String(text ?? "").trim());
      if (!value) return;
      state.intents = [...state.intents, stamp({ text: value })].slice(-CAPS.intents);
    },

    addCall(call) {
      if (!call?.tool) return;
      state.calls = [...state.calls, stamp(call)].slice(-CAPS.calls);
    },

    addFlag(flag) {
      if (!flag?.kind) return;
      state.flags = [...state.flags, stamp(flag)].slice(-CAPS.flags);
      state.revision++;
      decisions.clear();
    },

    lastPrompt() {
      return state.prompts.at(-1)?.text;
    },

    flagCount() {
      return state.flags.length;
    },

    counts() {
      return {
        prompts: state.prompts.length,
        intents: state.intents.length,
        calls: state.calls.length,
        flags: state.flags.length,
      };
    },

    flags() {
      return state.flags.map((flag) => ({ ...flag }));
    },

    calls() {
      return state.calls.map((call) => ({ ...call }));
    },

    /** The `context` object jev-guard sends with every question. Empty keys are dropped. */
    buildContext() {
      const context = {
        user_recent_messages: dedupe(state.prompts.map((prompt) => prompt.text)).slice(-3).map(clip),
        assistant_intent: clip(state.intents.at(-1)?.text ?? ""),
        recent_tool_calls: state.calls
          .slice(-6)
          .map((call) => `${call.tool} ${call.preview}${call.level && call.level !== "allow" ? ` [${call.level}]` : ""}`),
        flagged_untrusted_content: state.flags
          .slice(-5)
          .map((flag) => `${flag.kind} from ${flag.source ?? flag.tool ?? "unknown"}${flag.p ? ` (p=${flag.p})` : ""}${flag.excerpt ? `: "${flag.excerpt}"` : ""}`),
      };
      for (const key of Object.keys(context)) if (!context[key] || context[key].length === 0) delete context[key];
      return Object.keys(context).length ? context : undefined;
    },

    /** Memoize one assessment per (tool, input) until the session context changes or the TTL lapses.
     *  onPermissionRequest and beforeToolCall both come through here, so one call shares one Jev round-trip. */
    decision(key, create) {
      const at = now();
      const hit = decisions.get(key);
      if (hit && hit.rev === state.revision && at - hit.at < decisionTtl) return hit.promise;

      const entry = { rev: state.revision, at, promise: Promise.resolve().then(create) };
      decisions.set(key, entry);
      if (decisions.size > maxDecisions) {
        for (const [olderKey, older] of decisions) {
          if (decisions.size <= maxDecisions) break;
          if (older.promise !== entry.promise) decisions.delete(olderKey);
        }
      }
      entry.promise.catch(() => {
        if (decisions.get(key) === entry) decisions.delete(key);
      });
      return entry.promise;
    },

    /** Remember that the engine was about to show its own permission prompt for this call. */
    rememberPermissionAsked(key) {
      asked.set(key, now() + permissionTtl);
      if (asked.size > maxDecisions) {
        for (const [olderKey, until] of asked) {
          if (asked.size <= maxDecisions) break;
          if (until < now()) asked.delete(olderKey);
        }
      }
    },

    /** Consume the marker: true when the person was already asked for this exact call. */
    takePermissionAsked(key) {
      const until = asked.get(key);
      asked.delete(key);
      return typeof until === "number" && until >= now();
    },
  };
}

/** Stable, bounded key for a tool call. Long string fields (a write_file body) are fingerprinted, not stored. */
export function callKey(tool, input) {
  let body;
  try {
    body =
      tool === "shell_command"
        ? `${input?.command ?? ""}\u0000${Array.isArray(input?.args) ? input.args.join("\u0000") : ""}\u0000${input?.directory ?? ""}`
        : JSON.stringify(input ?? {}, (_key, value) =>
            typeof value === "string" && value.length > 4096 ? `${value.slice(0, 2048)}…${value.slice(-1024)}` : value,
          );
  } catch {
    body = String(input);
  }
  return `${tool}:${createHash("sha1").update(body).digest("hex").slice(0, 16)}`;
}
