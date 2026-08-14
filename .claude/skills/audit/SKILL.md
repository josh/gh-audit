---
name: audit
description: Run gh-audit over all active repos and triage each finding interactively — mute it, get walked through fixing it, or tune the rule. Use when asked to audit repos, run gh-audit over everything, or triage audit findings.
---

# Interactive repo audit

Run `gh-audit` in the background and triage every finding with the user, one at a
time, as the output streams in.

`/audit` audits all active repos. `/audit <repo>` or `/audit --rule <name>` scopes
it down — pass any arguments straight through to `gh_audit.py`.

## 1. Start the run

Read the mute list first (see **Mute** below) so muted findings never reach a prompt.

Then launch in the background with Bash `run_in_background: true`, writing stdout to
a file in the session scratchpad and stderr to a separate one. Never write run
artifacts into the gh-audit checkout.

```bash
uv run python -u gh_audit.py --active > <scratchpad>/out 2> <scratchpad>/err
```

Three things that will bite if ignored:

- **`uv run python gh_audit.py`, never `uv run gh-audit`.** `pyproject.toml` has no
  `[build-system]`, so the console script falls through to a stale Nix binary and
  silently runs old code.
- **`-u` is mandatory.** Nothing in `gh_audit.py` flushes. Redirected to a file,
  stdout block-buffers and nothing appears for minutes, which defeats the whole
  point of triaging while the run proceeds.
- **Exit code is always 0.** `main` discards each rule's result. Detect completion by
  process exit, never by status.

A full `--active` run is roughly 20 seconds per repo — about 20 minutes over ~60
repos. Do not wait for it. Start triaging as soon as the first lines land.

## 2. Read the stream

Poll the output file for new lines, tracking an offset so you re-read only what's new.
Findings arrive repo-by-repo in rule-definition order.

Strip ANSI, then parse:

```
^(?P<repo>[^:]+): (?P<level>error|warn): (?P<msg>.+) \[(?P<rule>[^\]]+)\]$
```

For example:

```
josh/trakt-collection: error: Missing README file [missing-readme]
josh/trakt-collection: error: Dependabot should be enabled for nix ecosystem [nix-dependabot]
```

Before prompting on anything:

- **Drop muted findings.** Match `(repo, rule)` or `(*, rule)`. Keep a count and
  report the suppressed total at the end so mutes stay visible rather than becoming
  invisible policy.
- **Dedupe on `(repo, rule)`.** Two rule names are defined twice — `git-size` and
  `missing-ruff` each have an error and a warning definition emitting the same
  message. Collapse them into one prompt and mention both levels. Same collision
  means `--rule missing-ruff` runs both definitions.
- **Note each decision as you make it** in a scratchpad file, so an interrupted loop
  resumes instead of re-asking. (Resume is within-session only; the scratchpad
  doesn't outlive the session. Mutes are permanent — they live in memory.)

## 3. Triage each finding

One prompt per finding, in arrival order. Before asking, actually understand it:

1. `grep -n 'name="<rule>"' gh_audit.py`, then read that `@define_rule` block and its
   check body.
2. Explain in plain language what the rule asserts and what specifically failed for
   this repo — not a restatement of the message.
3. Pull cheap read-only evidence when it sharpens the explanation, e.g.
   `gh repo view josh/<name> --json description,topics`.

Then ask with `AskUserQuestion`. Exactly four options, exactly one suffixed
`(Recommended)`. Use `Decision` as the `header` (rule names exceed the 12-char
limit) and put `repo — rule (level)` in the question text.

| Option     | Meaning                                                                |
| ---------- | ---------------------------------------------------------------------- |
| **Mute**   | Not a real problem here. Record it; never prompt for it again.         |
| **Fix**    | Walk the user through fixing it themselves.                            |
| **Adjust** | The rule itself is wrong or over-matching; tune `gh_audit.py`.         |
| **Skip**   | Not now. Nothing is written to memory; it will surface again next run. |

Which one to recommend:

- **Mute** when the rule is structurally inapplicable to this repo — a
  Python-packaging rule firing on a Nix or JS repo, a release rule on a non-package
  repo, a preference-shaped rule (`no-discussions`, `no-wiki`) on a repo the user
  doesn't care about.
- **Adjust** when the check is at fault — it fires on a repo that plainly satisfies
  the rule's intent, or it fires on nearly every repo, which usually means the
  threshold or matcher is off.
- **Fix** otherwise. This is the default: the finding is simply correct.
- Never recommend **Skip**. It's always offered, never suggested — it exists so the
  user can defer without being forced into a permanent decision.

The recommendation is a suggestion. The user picks.

## 4. Mute

Keep all mutes in one memory file,
`/Users/josh/.claude/projects/-Users-josh-Developer-gh-audit/memory/gh-audit-mutes.md`
(`type: feedback`). Append a row; never create a memory file per mute.

```markdown
| repo                  | rule           | why                            |
| --------------------- | -------------- | ------------------------------ |
| josh/trakt-collection | missing-mypy   | not a typed project            |
| \*                    | no-discussions | doesn't want discussions, ever |
```

`*` in the repo column mutes the rule everywhere. The Mute option is repo-scoped by
default — the user can ask for rule-wide via the free-text **Other**. Always capture
a real reason in the `why` column; a mute with no rationale is unreviewable later.

On first creation, add the one-line pointer to `MEMORY.md` and link
`[[jj-atomic-change-workflow]]` and `[[uv-run-nix-binary-gotcha]]` from the body.

## 5. Fix

Advisory, not hands-on. Name the exact file or setting, give the concrete command or
snippet to paste, and point at the local checkout (`~/Developer/<name>`) if there is
one. Do not edit other repos or change GitHub settings unless asked to in that
moment. Collect these for the wrap-up.

**Then stop and end the turn.** Do not roll straight into the next finding. The user
may want to apply the fix, ask about it, or hand it back to you — none of which they
can do if the next prompt is already on screen. Resume triage when they reply.

## 6. Adjust

Edit the rule in `gh_audit.py`, then land it immediately as its own atomic change:

```bash
uv run python gh_audit.py --rule <name> --active     # confirm the tuning worked
uv run ruff format --diff . && uv run ruff check . && uv run mypy .
jj git fetch --remote origin
jj new main@origin -m "<why, one line, under 72 chars>"
jj bookmark create <descriptive-name> -r @
jj git push --bookmark <descriptive-name>
```

- **Never open a PR.** The user opens, reviews, and merges them.
- Re-fetch before each `jj new` — `main@origin` moves during the session as they merge.
- There is no test suite; ruff and mypy are the full gate.
- Then resume triage where it left off.

## 7. Skip

Note it in the session scratchpad so the loop doesn't re-ask, and move on. Write
nothing to memory — a skip is not a mute and leaves no trace past this session.

## 8. Wrap up

Report: findings triaged, split by Mute / Fix / Adjust / Skip; findings auto-suppressed
by existing mutes; bookmarks pushed and awaiting review; and the accumulated fix list as
an actionable checklist.
