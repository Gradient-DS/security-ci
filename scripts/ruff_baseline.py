"""Check that every ruff config in a repository meets the org baseline.

The baseline is pre-commit/ruff-baseline.toml. A config may add rules and
settings; it may not drop a baseline rule family or change line length,
docstring convention or quote style.

Settings are resolved from the TOML files themselves, following `extend`,
rather than from `ruff check --show-settings`: that output does not include the
pydocstyle convention, and it needs a Python file under every config to resolve.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LINE_LENGTH = 120
FAMILIES = ("E", "F", "W", "I", "UP", "B", "SIM", "D")
CONVENTION = "google"
QUOTE_STYLE = "double"

# Ruff's own defaults, for settings a config leaves out.
DEFAULT_LINE_LENGTH = 88
DEFAULT_SELECT = ("E4", "E7", "E9", "F")
DEFAULT_QUOTE_STYLE = "double"

# The order ruff prefers when one directory holds several configs.
CONFIG_NAMES = (".ruff.toml", "ruff.toml", "pyproject.toml")


class ConfigError(Exception):
    """A config that cannot be read, or whose `extend` chain is broken."""


@dataclass
class Layer:
    """One file of an `extend` chain, as ruff reads it."""

    path: Path
    table: dict


@dataclass
class Result:
    """The baseline problems found in one config; empty means it conforms."""

    path: Path
    problems: list[str] = field(default_factory=list)


def ruff_table(path: Path) -> dict | None:
    """Return the ruff settings in `path`; None for a pyproject.toml without [tool.ruff]."""
    try:
        doc = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    if path.name == "pyproject.toml":
        return doc.get("tool", {}).get("ruff")
    return doc


def chain(path: Path) -> list[Layer]:
    """Return the `extend` chain of `path`, base first."""
    layers: list[Layer] = []
    seen: set[Path] = set()
    current: Path | None = path.resolve()
    while current is not None:
        if current in seen:
            raise ConfigError(f"{path}: `extend` cycle through {current}")
        seen.add(current)
        if not current.is_file():
            raise ConfigError(f"{path}: extended config {current} does not exist")
        table = ruff_table(current)
        if table is None:
            raise ConfigError(f"{current}: no [tool.ruff] table")
        layers.append(Layer(current, table))
        ext = table.get("extend")
        current = (current.parent / Path(ext).expanduser()).resolve() if ext else None
    return list(reversed(layers))


def _lint(table: dict, key: str):
    # `[lint]` is current; top-level rule settings are the deprecated spelling ruff still reads.
    lint = table.get("lint", {})
    return lint[key] if key in lint else table.get(key)


def _merged(layers: list[Layer], *keys: str):
    value = None
    for layer in layers:
        node = layer.table
        for key in keys:
            node = node.get(key) if isinstance(node, dict) else None
        if node is not None:
            value = node
    return value


def selected_families(layers: list[Layer]) -> set[str]:
    """Return the baseline families that are selected and not ignored as a whole.

    Mirrors ruff's layering: a layer's `select` replaces what came before (its
    ignores included), `extend-select` and `ignore` add to it. Only a whole
    family counts: `E4` selects part of E, and ignoring `E501` leaves E selected.
    """
    selected: set[str] = set(DEFAULT_SELECT)
    ignored: set[str] = set()
    for layer in layers:
        select = _lint(layer.table, "select")
        if select is not None:
            selected, ignored = set(select), set()
        selected |= set(_lint(layer.table, "extend-select") or ())
        ignored |= set(_lint(layer.table, "ignore") or ())
        ignored |= set(_lint(layer.table, "extend-ignore") or ())
    if "ALL" in ignored:
        return set()
    return {f for f in FAMILIES if (f in selected or "ALL" in selected) and f not in ignored}


def check(path: Path) -> Result:
    """Check the config at `path` against the baseline."""
    result = Result(path)
    try:
        layers = chain(path)
    except ConfigError as exc:
        result.problems.append(str(exc))
        return result

    line_length = _merged(layers, "line-length") or DEFAULT_LINE_LENGTH
    if line_length != LINE_LENGTH:
        result.problems.append(f"line-length is {line_length}, the baseline is {LINE_LENGTH}")

    missing = [f for f in FAMILIES if f not in selected_families(layers)]
    if missing:
        result.problems.append(f"lint.select is missing baseline rule families: {', '.join(missing)}")

    convention = _merged(layers, "lint", "pydocstyle", "convention") or _merged(layers, "pydocstyle", "convention")
    if convention != CONVENTION:
        result.problems.append(f"lint.pydocstyle.convention is {convention!r}, the baseline is {CONVENTION!r}")

    quote_style = _merged(layers, "format", "quote-style") or DEFAULT_QUOTE_STYLE
    if quote_style != QUOTE_STYLE:
        result.problems.append(f"format.quote-style is {quote_style!r}, the baseline is {QUOTE_STYLE!r}")
    return result


def tracked_files(root: Path) -> list[Path]:
    """Return the files git tracks under `root`, so untracked checkouts (tooling, node_modules) are ignored."""
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True, text=True
    ).stdout
    return [root / p for p in out.split("\0") if p]


def discover(files: list[Path]) -> list[Path]:
    """Return the ruff configs among `files`, one per directory, the one ruff would use."""
    by_dir: dict[Path, list[Path]] = {}
    for f in files:
        if f.name in CONFIG_NAMES:
            by_dir.setdefault(f.parent, []).append(f)
    configs = []
    for directory in sorted(by_dir):
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate not in by_dir[directory]:
                continue
            try:
                if ruff_table(candidate) is None:
                    continue
            except ConfigError:
                pass  # reported by check()
            configs.append(candidate)
            break
    return configs


def main(argv: list[str] | None = None) -> int:
    """Check every ruff config in the repository; exit 1 if any misses the baseline."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=".", type=Path, help="repository root (default: .)")
    root = parser.parse_args(argv).root.resolve()

    files = tracked_files(root)
    configs = discover(files)
    if not configs:
        if any(f.suffix == ".py" for f in files):
            print("::error::Python files but no ruff config (ruff.toml, .ruff.toml or [tool.ruff] in pyproject.toml)")
            return 1
        print("No Python and no ruff config: nothing to check.")
        return 0

    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    failed = False
    for config in configs:
        result = check(config)
        rel = config.relative_to(root)
        if not result.problems:
            print(f"{rel}: meets the org ruff baseline")
            continue
        failed = True
        for problem in result.problems:
            print(f"::error file={rel}::{problem}" if annotate else f"{rel}: {problem}")
    if failed:
        print("See pre-commit/ruff-baseline.toml in Gradient-DS/security-ci for the baseline.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
