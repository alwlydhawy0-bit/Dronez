"""Red-team corpus and scoring for the guardrail layer (`TM-10`).

The corpus is data, never instructions. Nothing here is executed; it is fed to the
sanitizer and to schema validators as untrusted text, which is how the rest of the
system is required to treat external content anyway (CLAUDE.md §10.4).
"""

from redteam.corpus import (
    BENIGN_CONTROLS,
    CORPUS,
    BenignCase,
    InjectionCase,
    Technique,
    cases_using,
    corpus_for_channel,
)
from redteam.report import (
    BenignOutcome,
    CaseOutcome,
    CorpusReport,
    score_corpus,
    techniques_covered,
)

__all__ = [
    "BENIGN_CONTROLS",
    "CORPUS",
    "BenignCase",
    "BenignOutcome",
    "CaseOutcome",
    "CorpusReport",
    "InjectionCase",
    "Technique",
    "cases_using",
    "corpus_for_channel",
    "score_corpus",
    "techniques_covered",
]
