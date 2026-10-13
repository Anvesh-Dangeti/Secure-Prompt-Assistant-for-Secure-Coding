"""Stage A -- explain the finding in terms of *this* code (Paper 1: explained feedback).

The default explanation is built from templates and the extracted entities,
with no model involved: "`user_id` comes from the HTTP request (`request.args`)
and is formatted into the SQL text passed to `cursor.execute`." It is
deterministic, costs nothing and cannot hallucinate.

Optionally a local model rewrites the explanation. Its answer is untrusted:
it is schema-validated, length-capped, must still name the code's entities,
and must not contain instruction-like text (it is forwarded into the prompt
outside the untrusted-code delimiters). Any failure falls back to the template
and the fallback is recorded -- an explanation is advisory, so falling back is
safe, but it must never be silent.

The handling directive (*how* to fix) always comes from the guidance table,
never from the model, because the linter checks prompts against that table.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.context import FindingContext
from app.ai.delimiting import INERT_INSTRUCTION, wrap_untrusted
from app.ai.guidance import guidance_for
from app.ai.injection import injection_phrases
from app.ai.providers.base import ChatMessage, LLMProvider, ProviderError


@dataclass(frozen=True)
class Explanation:
    text: str            # what flows where + why it matters, about this code
    source: str          # "template" | "<provider>:<model>"
    note: str | None = None


class _ModelExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    explanation: str = Field(min_length=20, max_length=600)


def template_explanation(ctx: FindingContext) -> Explanation:
    g = guidance_for(ctx.cwe)
    slots = ctx.slots()
    return Explanation(f"{g.render('explain', slots)} {g.render('risk', slots)}", "template")


def _ask_model(ctx: FindingContext, provider: LLMProvider) -> Explanation:
    g = guidance_for(ctx.cwe)
    block = wrap_untrusted(ctx.code, ctx.file_path, ctx.lines_label)
    ask = (
        f"Explain to a developer, in at most three sentences, why this code has a {g.name} ({ctx.cwe}) "
        f"weakness. Name the variables and calls involved. Do not write code.\n\n"
        f"{INERT_INSTRUCTION}\n\n{block.text}\n\n"
        f'Answer as JSON: {{"explanation": "..."}}'
    )
    completion = provider.complete([ChatMessage("user", ask)],
                                   json_schema=_ModelExplanation.model_json_schema())
    try:
        text = _ModelExplanation.model_validate_json(completion.text).explanation.strip()
    except ValidationError as exc:
        raise ValueError("explanation did not match the schema") from exc
    if injection_phrases(text):
        raise ValueError("explanation contained instruction-like text")
    if "```" in text or block.nonce in text:
        raise ValueError("explanation contained code or delimiter text")
    if ctx.entities and not any(e.split(".")[-1] in text for e in ctx.entities):
        raise ValueError("explanation did not refer to the flagged code")
    return Explanation(" ".join(text.split()), f"{provider.name}:{completion.model}")


def explain(ctx: FindingContext, provider: LLMProvider | None = None) -> Explanation:
    """Explain ``ctx``; with a generating ``provider`` try the model first."""
    fallback = template_explanation(ctx)
    if provider is None or not provider.generates:
        return fallback
    try:
        return _ask_model(ctx, provider)
    except (ProviderError, ValueError) as exc:
        return Explanation(fallback.text, fallback.source, note=f"{provider.name} explanation rejected: {exc}")
