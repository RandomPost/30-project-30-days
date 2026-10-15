# CS-05: STRIDE threat model of File Browser

[THREAT_MODEL.md](THREAT_MODEL.md) is a STRIDE threat model of
[filebrowser/filebrowser](https://github.com/filebrowser/filebrowser) (Go web app with
logins, uploads, share links, a REST API and an optional command runner), pinned to commit
`833d908884d5c801f30f5c098d7977177eb3a36b`. It contains a Mermaid data-flow diagram, trust
boundaries, 14 ranked threats (likelihood x impact) with mitigations, things that look fine,
and what was not verified.

Headline: the upstream project announced it is archived as of 2026-09-01 with no further
security fixes, so every unmitigated threat in the model is permanent.

## How it was made
Three read-only subagents explored the codebase in parallel (architecture and trust
boundaries; entry points and auth; storage and secrets). Their reports were merged and each
citation was re-checked by hand. All findings come from reading the code; nothing was exploited.

## Keeping the citations honest
Every `path:LINE` reference is generated from a quoted fragment, so it cannot silently drift.

```bash
git clone --depth 1 https://github.com/filebrowser/filebrowser /tmp/fb
git -C /tmp/fb checkout 833d908884d5c801f30f5c098d7977177eb3a36b   # the analysed commit
python scripts/check_citations.py /tmp/fb      # verifies THREAT_MODEL.md + citations.tsv
python scripts/render.py scripts/threat_model.tmpl.md /tmp/fb .      # regenerate after edits
pip install pytest && FILEBROWSER_CHECKOUT=/tmp/fb pytest
```

Edit `scripts/threat_model.tmpl.md`, not `THREAT_MODEL.md`: `[[path|fragment]]` in the
template becomes `` `path:LINE` `` in the output and a row in `citations.tsv`.
Note: a shallow clone is at HEAD, which is the analysed commit unless upstream has moved.
