# cmd-mod-jev-guard

Auto mode for Command Code, powered by [Jev](https://typesafe.ai/).

Every tool call is risk-scored with the session's context and answered with
**deny / ask / allow**; risky ones wait for your approval; calls that follow an
instruction planted in something the agent read are denied; tool results are
scanned for prompt injection; and instruction files (skills, `AGENTS.md`,
`CLAUDE.md`, rules) are swept for behavior their installer would not expect.

This is a [Command Code mod](https://commandcode.ai/docs/mods) implementing
[jev-guard](https://github.com/leepokai/jev-guard) on top of the mod API. The
policy, questions, thresholds and Jev client are vendored from jev-guard (MIT);
the Command Code integration is new.

## Why a mod instead of the existing hooks

jev-guard already ships an adapter that writes native hooks into
`~/.commandcode/settings.json`. Command Code's hook API is a strict subset of
what the policy needs:

| Capability | Native hooks | This mod |
|---|---|---|
| `deny` | yes | yes (`beforeToolCall`) |
| `ask` | **warning only** (hooks are allow/deny) | real confirm dialog; warning fallback headless |
| `allow` → auto-approve | impossible | `onPermissionRequest` → `'allow'` |
| `user_requested` context | no `UserPromptSubmit` event | `transformInput` captures every typed prompt |
| Result scanning | `additionalContext` append | `afterToolCall` `additionalContext` |
| Per-call overhead | spawn Node + import the CLI | in-process |

Run **one or the other**, not both: `/jev-guard doctor` warns if the native
hooks are still registered.

## Install

```bash
# local checkout, referenced in place
cmd mods add -g ./

# or a published package
cmd mods add -g npm:cmd-mod-jev-guard

# or no install at all, for the dev loop
cmd --mod ./src/mod.ts
```

Restart `cmd` (or `/reload`) after installing. `cmd mods inspect ./` lists the
hooks it registers.

### Credentials

The mod reads the same sources as jev-guard, in order:

1. `JEV_API_KEY` (TypeSafe), `AI_GATEWAY_API_KEY`, `VERCEL_OIDC_TOKEN`
2. `~/.jev-guard/config.json` (`jev-guard key <key>`)
3. `OPENROUTER_API_KEY`
4. `~/.commandcode/auth.json` — the key `cmd login` already stored, billed
   through the Command Code Provider API (`typesafe/jev`)

`JEV_BASE_URL` points at any System One server (for example a local
[Kev](https://github.com/jaredpalmer/kev)) and wins over all of the above.
`JEV_MODEL` overrides the model id.

No key? The guard fails **open** with one warning: a dead API must not freeze
the agent. Set `JEV_GUARD_FAIL_CLOSED=1` to deny instead.

## Commands

| Command | Does |
|---|---|
| `/jev-guard` or `/jev-guard status` | mode, thresholds, backend, session counts, last decision |
| `/jev-guard mode auto\|deny-only\|off` | switch at runtime (`deny-only` keeps hard denies only) |
| `/jev-guard scan [paths...]` | sweep instruction files (default: this project) |
| `/jev-guard check <tool> '<json>'` | assess one call, like `jev-guard check` |
| `/jev-guard clear` | drop session memory (the scan cache stays) |
| `/jev-guard doctor` | key/backend, conflicts with native hooks, cache size |

## Options

```
--mod-option jevMode=auto|deny-only|off   (default auto)
--mod-option jevAutoApprove=true|false    (default true)
--mod-option jevScan=true|false           (default true)
--mod-option jevSweep=project|all|none    (default project)
--mod-option jevStatus=true|false         (default true)
--mod-option jevFailClosed=true|false     (default false)
```

Env equivalents: `JEV_GUARD_MODE`, `JEV_GUARD_AUTO_APPROVE=0`,
`JEV_GUARD_SCAN=0`, `JEV_GUARD_SWEEP`, `JEV_GUARD_STATUS=0`,
`JEV_GUARD_FAIL_CLOSED`.

Thresholds are jev-guard's, unchanged:

| Variable | Default |
|---|---|
| `JEV_GUARD_DENY_SCORE` | `2.5` |
| `JEV_GUARD_ASK_SCORE` | `1.5` |
| `JEV_GUARD_ASK_P` | `0.75` |
| `JEV_GUARD_INJECT_P` | `0.6` |
| `JEV_GUARD_UNTRUSTED_P` | `0.7` |
| `JEV_GUARD_USER_P` | `0.85` |
| `JEV_GUARD_SKILL_P` / `JEV_GUARD_SKILL_SERIOUS_P` | `0.8` / `0.45` |
| `JEV_GUARD_TIMEOUT_MS` | `20000` |
| `JEV_GUARD_SKIP_TOOLS` / `JEV_GUARD_SKIP_SCAN` | unset |

## How decisions are made

```
deny if from_untrusted ≥ 0.7
deny if risk ≥ 2.5
allow if (risk ≥ 1.5 or approval ≥ 0.75) and user_requested ≥ 0.85
ask if risk ≥ 1.5 or approval ≥ 0.75
allow otherwise
```

- `beforeToolCall` enforces deny and ask. A deny becomes the tool result, so the
  run continues and the model can adapt. An ask opens a confirm dialog, unless
  Command Code already prompted for that same call (tracked per call, so you are
  never asked twice) or the session is headless (then it warns and proceeds).
- `onPermissionRequest` answers only `allow` verdicts with `'allow'` — that is
  the auto-approve half of auto mode. It never returns `'deny'`, because a deny
  there aborts the whole tool batch; the block in `beforeToolCall` is kinder.
- `transformInput` records what you typed; `message_end` records the assistant's
  intent. Together with recent decisions and flagged excerpts they form the
  `context` Jev sees, so "CI is green, force push main" turns a force push from
  ask into allow.
- `afterToolCall` scans results ≥ 200 chars for AI-directed text and appends the
  warning to the tool result. Reads of instruction files use the stricter
  "what would its installer not expect?" questions.
- `onSessionStart` sweeps the project's instruction files (cached by content
  hash in `cmd.store`), reports findings, and notes them in the system prompt.

Read-only tools (`read_file`, `glob`, `grep`, `web_fetch`, `task`, …) never cost
a Jev call. Results of local edit/search tools are never scanned.

## Privacy

Only what the decision needs is sent to your Jev backend: the tool name,
arguments (capped at 24k characters), cwd, the recent user prompts / assistant
intent / recent decisions / flagged excerpts, or the tool result text (capped at
60k characters, head and tail) for scans. Never the API key, the transcript,
environment variables, or files the agent did not read. Review
[TypeSafe's privacy policy](https://typesafe.ai/privacy) before pointing this at
sensitive repositories.

Like jev-guard, this is a guardrail, not a sandbox.

## Development

```bash
node --test test/*.test.js     # policy truth table, session cache, scan cache, factory
cmd mods inspect ./            # hooks/commands/flags the mod registers
cmd --mod ./src/mod.ts         # load without installing
node --check src/policy.js     # vendored modules are plain ESM
```

No build step: Command Code loads the TypeScript with jiti. The vendored modules
in `src/jev.js` and `src/policy.js` are plain ESM so the tests can import them
directly.

## Limitations

- Command Code only. Other agents still use jev-guard's own adapters.
- `onPermissionRequest` is expected to accept a Promise. If a host ignores it,
  auto-approve degrades to "you get the normal prompt"; deny/ask still work.
- Session memory is in-process. A resumed session starts with an empty context
  (the scan cache does persist).
- The policy is vendored from jev-guard; upstream changes need a re-sync.

## License

MIT. `src/jev.js` and `src/policy.js` are vendored from
[jev-guard](https://github.com/leepokai/jev-guard) (MIT), with attribution in
each file.
