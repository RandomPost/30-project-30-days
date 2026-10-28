"""Build a Batfish snapshot from the netgen source of truth plus an overlay.

Batfish cannot parse FRR flat config files (it treats them as IOS and rejects the
OSPF lines), so every device is rendered with netgen's IOS-style template for the
analysis. The addressing, VLANs and OSPF intent are the same; only the syntax
differs. Policy that netgen cannot express (ACLs) lives in overlay files, one per
device, appended to the rendered config."""

from __future__ import annotations

from pathlib import Path

from netgen.loader import load
from netgen.models import Inventory
from netgen.render import render_device
from netgen.validate import validate

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = ROOT.parent / "ne-05-netgen" / "data" / "sites.yml"
DEFAULT_OVERLAY = ROOT / "network" / "overlay"


def load_inventory(path: Path) -> Inventory:
    inv = load(Path(path))
    problems = validate(inv)
    if problems:
        raise ValueError(
            f"{path} is not a valid source of truth:\n  " + "\n  ".join(problems)
        )
    return inv


def render_for_batfish(inv: Inventory) -> dict[str, str]:
    """device name -> IOS-style config text (all platforms rendered as ios)."""
    out = {}
    for site in inv.sites:
        for dev in site.devices:
            out[dev.name] = render_device(
                site, dev.model_copy(update={"platform": "ios"})
            )
    return out


def build(source: Path, overlay: Path | None, out: Path) -> Path:
    """Write <out>/configs/<device>.cfg and return `out` (the snapshot directory)."""
    configs = render_for_batfish(load_inventory(source))
    overlay_files = (
        sorted(Path(overlay).glob("*.cfg"))
        if overlay and Path(overlay).exists()
        else []
    )
    unknown = [f.stem for f in overlay_files if f.stem not in configs]
    if unknown:
        raise ValueError(
            f"overlay files for devices not in the source of truth: {', '.join(unknown)}"
        )
    target = Path(out) / "configs"
    target.mkdir(parents=True, exist_ok=True)
    for name, text in configs.items():
        extra = ""
        ov = Path(overlay) / f"{name}.cfg" if overlay else None
        if ov is not None and ov.exists():
            extra = "!\n! --- overlay ---\n" + ov.read_text()
        body = text.rstrip().removesuffix("end").rstrip() + "\n" + extra + "end\n"
        (target / f"{name}.cfg").write_text(body)
    return Path(out)
