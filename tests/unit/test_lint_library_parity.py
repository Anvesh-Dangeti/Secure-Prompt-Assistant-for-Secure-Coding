"""The published lint library and this application are one linter, not two copies.

* the application's linter modules re-export the library's objects (one source of code);
* the library's bundled vocabulary and benchmark equal a fresh export from our data;
* the library renders the same fix-it sentences our prompt strategy uses;
* the library's stand-alone benchmark reproduces E1 exactly;
* the library never imports this application.
"""

from __future__ import annotations

import re
from pathlib import Path

import secure_prompt_lint
from secure_prompt_lint import bench, delimiting, engine, injection, redaction, tokens
from secure_prompt_lint.sentences import render
from secure_prompt_lint.vocabulary import all_vocabulary, all_weakness_terms, entry_for

import app.ai.delimiting
import app.ai.injection
import app.ai.tokens
import app.core.redaction
from app.ai import guidance
from app.ai.linter import engine as app_engine
from evaluation import e1_mutation
from evaluation.recorded_results import E1
from scripts.export_lint_data import stale
from tests._ai_support import all_contexts

LIB = Path(secure_prompt_lint.__file__).parent


def test_the_application_modules_are_the_library() -> None:
    assert app.ai.delimiting.wrap_untrusted is delimiting.wrap_untrusted
    assert app.ai.delimiting.split_prompt is delimiting.split_prompt
    assert app.ai.injection.injection_phrases is injection.injection_phrases
    assert app.ai.tokens.estimate_tokens is tokens.estimate_tokens
    assert app.core.redaction.redact is redaction.redact
    assert app_engine.lint is engine.lint


def test_the_bundled_data_is_a_current_export() -> None:
    assert stale() == [], "run: python scripts/export_lint_data.py"


def test_same_vocabulary_as_the_guidance_table() -> None:
    assert all_vocabulary() == guidance.all_vocabulary()
    assert all_weakness_terms() == guidance.all_weakness_terms()
    for g in guidance.all_guidance():
        entry = entry_for(g.cwe)
        assert (entry.name, entry.vocabulary, entry.weakness_terms) == (g.name, g.vocabulary, g.weakness_terms)


def test_same_fix_it_sentences_as_our_strategy() -> None:
    for ctx in all_contexts():
        g, entry = guidance.guidance_for(ctx.cwe), entry_for(ctx.cwe)
        for field in ("explain", "directive", "guard"):
            assert render(entry, field, ctx.slots()) == g.render(field, ctx.slots()), (ctx.rule_id, field)


def test_the_stand_alone_benchmark_reproduces_e1() -> None:
    published = bench.score(bench.load_cases())
    assert published == e1_mutation.run()
    assert published["constituent"] == E1["constituent"] and published["unchecked"] == E1["unchecked"]


def test_the_library_never_imports_the_application() -> None:
    pattern = re.compile(r"^\s*(from|import)\s+(app|dashboard|evaluation|scripts)\b", re.MULTILINE)
    offenders = [p.name for p in LIB.rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []
