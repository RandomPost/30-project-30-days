# cs-05-threat-model

A written STRIDE threat model of File Browser plus the tooling that keeps its citations true.

## Layout
- `THREAT_MODEL.md`: the deliverable (generated, do not edit by hand)
- `scripts/threat_model.tmpl.md`: source of the model; citations are `[[path|fragment]]`
- `scripts/render.py`: template + repo checkout -> `THREAT_MODEL.md` and `citations.tsv`
- `scripts/check_citations.py`: verifies every cited line still contains its fragment
- `citations.tsv`: path, line, fragment for each citation
- `tests/test_citations.py`: pytest suite (set `FILEBROWSER_CHECKOUT` for the live check)

## Commands
- Test: `pytest`; with the live check: `FILEBROWSER_CHECKOUT=/path/to/filebrowser pytest`
- Format: `black .`
- Check: `python scripts/check_citations.py /path/to/filebrowser`

## Conventions
- Edit the template, then re-render; never hand-edit line numbers
- Every claim cites a file and line, or says it is inferred or not verified
- Static reading only; do not present unexercised issues as confirmed exploits
- Treat subagent reports as leads: re-check each citation before it goes in the model
