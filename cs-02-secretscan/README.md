# secretscan

Finds API keys, AWS credentials, private keys and high-entropy strings in a directory,
with an allowlist for false positives, and wires the scanner into your workflow two ways.

```bash
pip install -e .
secretscan scan .            # scan a directory; exit 1 if anything is found
secretscan scan --staged     # scan what is staged in git
secretscan install-hook      # install the git pre-commit hook
```

## What it detects
AWS access key IDs and secret keys, PEM private keys, GitHub / Slack / Google tokens,
`api_key = "..."`-style assignments, and any quoted string of 24+ characters with
Shannon entropy >= 4.5 bits/char. Obvious placeholders (`example`, `xxxx`, repeated
characters) are ignored. Output redacts the secret and shows a fingerprint.

## Allowlist
Put a `.secretscan-allow` file in the directory you scan from:

```
path:docs/*.md           # ignore a glob of files
rule:high-entropy-string # ignore a rule everywhere
fp:3fa9c1d2e4b5          # ignore one finding (fingerprint from the output)
```

Or add `secretscan:ignore` to a line.

## Hook 1: git pre-commit
`secretscan install-hook` copies `hooks/pre-commit` into the repo's hooks directory.
On `git commit`, git runs it; it runs `secretscan scan --staged`, which scans the
**staged version** of each added/changed file (what will actually be committed, not
your working copy). Any finding makes the script exit non-zero, and git aborts the
commit. Bypass deliberately with `git commit --no-verify`.

## Hook 2: Claude Code PostToolUse
`.claude/settings.json` registers a `PostToolUse` hook for the `Write`, `Edit` and
`MultiEdit` tools. After Claude edits a file, Claude Code runs
`python3 -m secretscan hook` and sends it the tool event as JSON on stdin. The hook reads
`tool_input.file_path`, scans that file, and:

- no findings (or not a file edit): exits 0, Claude carries on silently
- findings: prints them to stderr and exits **2**, which Claude Code feeds back to
  Claude as feedback, so it can remove the secret itself

Open Claude Code in this folder (so `$CLAUDE_PROJECT_DIR` is `cs-02-secretscan`) after
`pip install -e .`, check it with `/hooks`, and ask Claude to write a file containing a
fake key.

Tests: `pytest`. Fake secrets are generated at runtime so the repo holds none.
