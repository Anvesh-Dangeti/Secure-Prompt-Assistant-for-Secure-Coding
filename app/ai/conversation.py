"""Lab mode: send a strategy's messages to a model and collect a schema-validated fix proposal.

Multi-turn strategies (RCI) are played as a conversation: each user message is
sent with the model's previous replies, exactly as a developer would paste them
one after another. Only the final turn is constrained to the fix schema; the
critique turns are free text, as in Paper 3.

The JSON shape is asked for in a short system note added *here*, by the lab
harness -- not in the strategy text -- so the prompts measured in the lab are
the same prompts developer mode shows. Token counts are summed over every call
(each call re-sends the conversation, which is what it really costs).

Nothing here applies or trusts the proposal: applying it in a scratch copy and
deciding whether it worked is the verification layer's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.ai.output_schema import FIX_SCHEMA, FixProposal, MalformedModelOutput, parse_fix_proposal
from app.ai.prompt_builder import PromptPlan
from app.ai.providers.base import ChatMessage, LLMProvider, ProviderError

FORMAT_NOTE = (
    "When you give the corrected code, reply with a JSON object: \"code\" holds the complete corrected "
    "replacement for the code between the untrusted_code markers, \"imports\" lists any new import statements, "
    "and \"summary\" says in one sentence what you changed."
)


@dataclass
class ConversationResult:
    strategy: str
    transcript: list[ChatMessage] = field(default_factory=list)
    proposal: FixProposal | None = None
    error: str | None = None          # "provider: ..." or "malformed: ..."
    model: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    params: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.proposal is not None


def run_conversation(plan: PromptPlan, provider: LLMProvider) -> ConversationResult:
    result = ConversationResult(plan.strategy, params=provider.describe())
    system = "\n\n".join(p for p in (plan.system, FORMAT_NOTE) if p)
    history = [ChatMessage("system", system)]
    last = len(plan.messages) - 1
    try:
        for i, message in enumerate(plan.messages):
            history.append(ChatMessage("user", message))
            completion = provider.complete(history, json_schema=FIX_SCHEMA if i == last else None)
            history.append(ChatMessage("assistant", completion.text))
            result.calls += 1
            result.model = completion.model
            result.prompt_tokens += completion.prompt_tokens or 0
            result.completion_tokens += completion.completion_tokens or 0
        result.proposal = parse_fix_proposal(history[-1].content, plan.nonce)
    except ProviderError as exc:
        result.error = f"provider: {exc}"
    except MalformedModelOutput as exc:
        result.error = f"malformed: {exc}"
    result.transcript = history
    return result
