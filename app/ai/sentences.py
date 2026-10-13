"""The sentences a remediation prompt is assembled from.

Shared by the strategies (which compose them) and the linter (whose fix-its
insert them), so a fix-it inserts exactly the sentence S7 would have had.

Two groups:

* the **security envelope** -- scope constraint, inert-data instruction,
  delimited code, output contract -- is identical in every strategy, S0
  included, so the strategy comparison varies only the security *guidance*;
* the **constituents** Paper 2 found security-sensitive -- opening anchor,
  entity binding, handling directive, guard -- which strategies include or not.
"""

from __future__ import annotations

from app.ai.context import FindingContext
from app.ai.guidance import CweGuidance


def _lines(ctx: FindingContext) -> str:
    label = ctx.lines_label
    return f"lines {label}" if "-" in label else f"line {label}"


def location(ctx: FindingContext) -> str:
    where = f"{ctx.file_path} ({_lines(ctx)})"
    if ctx.window_kind == "dependency" or not ctx.symbol:
        return where
    if ctx.symbol == "__main__":
        return f"the `__main__` block of {where}"
    return f"`{ctx.symbol}` in {where}"


def _binding_clause(ctx: FindingContext) -> str:
    src = ctx.sources[0].name if ctx.sources else None
    sink = ctx.sinks[0] if ctx.sinks else None
    if src and sink:
        return f", where `{src}` reaches `{sink}`"
    if src:
        return f", where `{src}` is used unsafely"
    if sink:
        return f", in the call to `{sink}`"
    target = next((t for t in ctx.targets if t != ctx.symbol), None)
    return f", in `{target}`" if target else ""


# ---- constituents -----------------------------------------------------------


def opening(ctx: FindingContext, g: CweGuidance) -> str:
    """Task, weakness, location and entity in sentence 0 (Paper 2: opening position matters most)."""
    if ctx.window_kind == "dependency":
        version = f" {ctx.package_version}" if ctx.package_version else ""
        return f"Fix the {g.name} ({g.cwe}) in {location(ctx)}: `{ctx.package}`{version} has known vulnerabilities."
    return f"Fix the {g.name} ({g.cwe}) in {location(ctx)}{_binding_clause(ctx)}."


def binding(ctx: FindingContext, g: CweGuidance) -> str:
    """Which input is at risk and which operation it reaches (entity binding)."""
    sentence = g.render("explain", ctx.slots())
    if ctx.entities and not any(e in sentence for e in ctx.entities):
        sentence = f"The flagged code is `{ctx.entities[0]}`. {sentence}"
    return sentence


def directive(ctx: FindingContext, g: CweGuidance) -> str:
    return g.render("directive", ctx.slots())


def guard(ctx: FindingContext, g: CweGuidance) -> str:
    return g.render("guard", ctx.slots())


# ---- envelope -----------------------------------------------------------------


def scope(ctx: FindingContext) -> str:
    if ctx.window_kind == "dependency":
        return f"Change only the `{ctx.package}` requirement and do not modify any other dependency."
    if ctx.symbol and ctx.symbol != "__main__" and ctx.window_kind in {"function", "lines"}:
        return (f"Change only the code between the markers: do not rename `{ctx.symbol}`, do not modify "
                f"anything else in the file, and keep its behaviour for valid input.")
    return "Change only the code between the markers and do not modify anything else in the file."


def output_contract(ctx: FindingContext) -> str:
    if ctx.window_kind == "dependency":
        return "Return the corrected requirements line."
    return ("Return the complete corrected version of the code between the markers. If the fix needs a new "
            "import, give the import statement separately.")


def scanner_report(ctx: FindingContext) -> str:
    """The raw scanner output -- Paper 1's 'direct feedback'."""
    rule = ctx.rule_id.rsplit(".", 1)[-1]
    return f'The static analyser {ctx.tool} (rule {rule}, severity {ctx.severity}) reported: "{ctx.message}"'


def classification(ctx: FindingContext) -> str:
    parts = [f"severity {ctx.severity}"]
    if ctx.owasp:
        parts.insert(0, f"OWASP {ctx.owasp}")
    if ctx.vulns:
        parts.append("advisories " + ", ".join(ctx.vulns))
    return "Classification: " + "; ".join(parts) + "."
