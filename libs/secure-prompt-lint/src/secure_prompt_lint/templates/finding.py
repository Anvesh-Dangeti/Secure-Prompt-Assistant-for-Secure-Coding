"""What a prompt is built from: one scanner finding and the code around it.

A ``Finding`` holds only facts a prompt needs: where the weakness is, which
code to show, and the names involved -- the untrusted *sources* (with where
their value comes from), the *sinks* they reach, module-level *targets*,
*constants*, and for a vulnerable dependency the package, its version, its
advisories and the version that fixes them.

The names are identifiers, not free text: the Secure Prompt Assistant reads
them from the code with Python's ``ast`` module and from package metadata, so
nothing written in the scanned repository can reach a prompt's instructions.
Fill them the same way. The ``code`` itself is untrusted; it is always sent
inside nonce-delimited markers with an instruction to treat it as data.

Any object with these attributes works (the strategies read attributes, never
the type), so an application can pass its own context object directly.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from typing import Any

#: what a code window can be; a dependency finding is about a requirements line
WINDOW_KINDS = ("function", "lines", "main-block", "statement", "dependency")


@dataclass(frozen=True)
class Source:
    """An untrusted value and where it comes from, e.g. ``host`` / "the HTTP request (`request.args`)"."""

    name: str
    origin: str


@dataclass(frozen=True)
class Finding:
    cwe: str | None                 # e.g. "CWE-78"; None words the prompt for an unclassified weakness
    file_path: str
    code: str                       # the code window sent to the assistant (untrusted)
    window_start: int = 1
    window_end: int | None = None   # None: a one-line window
    window_kind: str = "lines"      # one of WINDOW_KINDS
    symbol: str | None = None       # the function (or "__main__") the window covers
    sources: tuple[Source, ...] = ()
    sinks: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    constants: tuple[str, ...] = ()
    tool: str = ""                  # the scanner's own report, quoted by S0-S6 and S8
    rule_id: str = ""
    severity: str = "MEDIUM"
    message: str = ""
    owasp: str | None = None        # e.g. "A03:2021 Injection"
    package: str | None = None      # dependency findings only
    package_version: str | None = None
    vulns: tuple[str, ...] = ()
    fixed_version: str | None = None

    def __post_init__(self) -> None:
        if self.window_kind not in WINDOW_KINDS:
            raise ValueError(f"window_kind must be one of {', '.join(WINDOW_KINDS)}")

    @property
    def lines_label(self) -> str:
        end = self.window_start if self.window_end is None else self.window_end
        return f"{self.window_start}-{end}" if end != self.window_start else str(self.window_start)

    @property
    def entities(self) -> tuple[str, ...]:
        """Every name the linter accepts as binding the prompt to this finding."""
        names = [s.name for s in self.sources] + list(self.sinks) + list(self.targets)
        if self.package:
            names.append(self.package)
        return tuple(dict.fromkeys(names))

    def slots(self) -> dict[str, str]:
        """Values for the sentence templates of the vocabulary table."""
        first_source = self.sources[0] if self.sources else None
        return {
            "source": first_source.name if first_source else "",
            "origin": first_source.origin if first_source else "",
            "sink": self.sinks[0] if self.sinks else "",
            "target": self.targets[0] if self.targets else "",
            "base": self.constants[0] if self.constants else "",
            "symbol": self.symbol or "",
            "package": self.package or "",
            "version": self.package_version or "",
            "fixed": self.fixed_version or "",
            "vulns": ", ".join(self.vulns),
            "cwe": self.cwe or "",
        }

    # ---- conversion ----------------------------------------------------------

    @classmethod
    def from_context(cls, obj: Any) -> Finding:
        """Copy the fields this class has from any object that has them (an application's own context)."""
        values = {f.name: getattr(obj, f.name) for f in fields(cls) if hasattr(obj, f.name)}
        values["sources"] = tuple(Source(s.name, s.origin) for s in values.get("sources", ()))
        return cls(**_tuples(values))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        """Build a finding from JSON-shaped data; unknown keys are refused so a typo is not silently ignored."""
        if not isinstance(data, Mapping):
            raise ValueError("a finding must be a JSON object")
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"unknown finding field(s): {', '.join(unknown)}")
        for required in ("cwe", "file_path", "code"):
            if required not in data:
                raise ValueError(f"a finding needs '{required}'")
        values = dict(data)
        values["sources"] = tuple(_source(s) for s in values.get("sources", ()))
        return cls(**_tuples(values))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "sources":
                value = [{"name": s.name, "origin": s.origin} for s in value]
            elif isinstance(value, tuple):
                value = list(value)
            out[f.name] = value
        return out


_TUPLE_FIELDS = ("sinks", "targets", "constants", "vulns")


def _tuples(values: dict[str, Any]) -> dict[str, Any]:
    for name in _TUPLE_FIELDS:
        if name in values:
            value = values[name]
            if isinstance(value, str) or not isinstance(value, Iterable):
                raise ValueError(f"'{name}' must be a list of names")
            values[name] = tuple(str(v) for v in value)
    return values


def _source(raw: Any) -> Source:
    if isinstance(raw, Mapping) and isinstance(raw.get("name"), str):
        return Source(raw["name"], str(raw.get("origin", "")))
    if isinstance(raw, (list, tuple)) and len(raw) == 2:
        return Source(str(raw[0]), str(raw[1]))
    raise ValueError("each source must be {\"name\": ..., \"origin\": ...} or a [name, origin] pair")
