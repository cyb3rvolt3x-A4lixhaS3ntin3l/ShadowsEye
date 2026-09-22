"""Packaging / entry-point checks — no live network."""

from __future__ import annotations

import importlib
import importlib.metadata as md


def test_shadowseye_module_imports_and_exposes_cli() -> None:
    mod = importlib.import_module("shadowseye")
    assert callable(getattr(mod, "main", None))
    assert callable(getattr(mod, "cli", None))
    assert callable(getattr(mod, "build_parser", None))


def test_console_script_entry_metadata() -> None:
    """Editable/install metadata must resolve the shadowseye console entry."""
    eps = md.entry_points()
    if hasattr(eps, "select"):
        scripts = list(eps.select(group="console_scripts"))
    else:  # pragma: no cover - older importlib.metadata
        scripts = list(eps.get("console_scripts", []))

    by_name = {ep.name: ep for ep in scripts}
    assert "shadowseye" in by_name, (
        "console_scripts entry 'shadowseye' missing — run: pip install -e ."
    )
    ep = by_name["shadowseye"]
    assert ep.value in {"shadowseye:cli", "shadowseye:cli()"}
    # Load the entry and ensure it is callable (still no network).
    loaded = ep.load()
    assert callable(loaded)
