import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
COMPASS = ROOT / "docs/HODLXXI_PROJECT_COMPASS.md"


SECTIONS = (
    "Mission",
    "Original trust model",
    "Normative invariants",
    "Objective Bitcoin facts versus social/protocol assertions",
    "Sponsor responsibility and downstream failure",
    "Revocation, quarantine and historical preservation",
    "Self-hosting and node sovereignty",
    "E923 as HODLXXI V1 genesis versus E923 as a live central server",
    "Portable CRT proof versus local JWT",
    "Legacy infrastructure that remains useful",
    "Legacy behavior that must eventually be retired",
    "Current implementation boundary",
    "Production migration and release trains",
    "Future signed trust-bundle and replica layer",
    "Explicit non-goals",
    "Open operator decisions",
    "Mandatory future-PR alignment checklist",
    "Compass versioning and change control",
)


FUTURE_PR_QUESTIONS = (
    "Which Compass invariants does it touch?",
    "Does it change HODLXXI V1 or define a new version/profile?",
    "Does it change production behavior?",
    "Does it change membership, authorization, admin or JWT boundaries?",
    "Does it introduce central live-server dependency?",
    "Does it preserve reciprocal descriptor observation?",
    "Does it preserve historical evidence during revocation?",
    "Is the result local, portable, signed or universally authoritative?",
    "What fails closed?",
    "What is the rollback?",
    "What is explicitly deferred?",
    "What user-visible outcome changes?",
)


OPERATOR_DECISIONS = (
    "exact revocation authority",
    "bilateral acknowledgement format",
    "sponsor response/remediation deadline",
    "descendant behavior after sponsor revocation",
    "re-sponsorship rules",
    "lifecycle event signing",
    "event sequence and previous-event chaining",
    "graph checkpoints",
    "conflict and fork resolution",
    "descriptor privacy versus portability",
    "proof freshness policy",
    "trust-bundle export/import format",
    "independent-node conformance requirements",
    "whether and how future non-E923 graph profiles are supported",
)


NON_GOALS = (
    "KYC",
    "legal identity",
    "proof of independent human key ownership",
    "custody",
    "token sale",
    "investment promise",
    "profit promise",
    "universal reputation score",
    "automatic administrator access",
    "global JWT issuer",
    "completed federation",
    "proof that no fork or conflicting lifecycle history exists",
    "proof of reciprocal descriptor possession unless separately acknowledged and signed",
)


def read_compass():
    assert COMPASS.is_file()
    return COMPASS.read_text(encoding="utf-8")


def normalized(text):
    return " ".join(text.split())


def test_compass_exists_and_is_linked_from_documentation_index():
    read_compass()
    index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
    assert "[HODLXXI_PROJECT_COMPASS.md](HODLXXI_PROJECT_COMPASS.md)" in index


def test_required_sections_and_exact_invariant_heading_set():
    text = read_compass()
    for section in SECTIONS:
        assert f"## {section}" in text
    for number in range(1, 17):
        invariant_id = f"HC-{number:02d}"
        assert len(re.findall(rf"^### {invariant_id} — .+$", text, re.MULTILINE)) == 1


def test_foundational_terms_and_mandatory_distinctions():
    text = normalized(read_compass()).lower()
    for phrase in (
        "Alice stores and observes Bob's watch-only descriptor",
        "Bob reciprocally stores and observes Alice's descriptor",
        "reciprocal descriptor custody",
        "must independently retain enough descriptor/script information",
        "revocation preserves evidence",
        "E923 is the fixed genesis participant of HODLXXI V1",
        "E923 is not an always-online central server",
        "JWTs are local to the issuing runtime",
        "Portable signed trust bundles are not yet implemented",
        "legacy balance-to-FULL shortcut",
        "shadow comparison",
        "production deployment is not claimed",
        "participant selection",
        "monitoring",
        "containment",
        "revocation",
        "remediation",
    ):
        assert phrase.lower() in text


def test_future_pr_questions_and_operator_decisions_are_complete():
    text = read_compass()
    for required in FUTURE_PR_QUESTIONS + OPERATOR_DECISIONS:
        assert required in text


def test_all_mandatory_non_goals_are_explicit():
    text = read_compass().lower()
    for non_goal in NON_GOALS:
        assert non_goal.lower() in text


def test_authority_and_current_implementation_boundaries_are_explicit():
    text = normalized(read_compass())
    for required in (
        "canonical project-direction and architectural-boundary document",
        "normative for future design and PR scope",
        "not itself a protocol proof",
        "not a legal contract",
        "not a deployment claim",
        "subordinate to executable Bitcoin consensus",
        "local unsigned snapshot-to-proof composition",
        "generic multi-genesis graph profiles",
        "Unsigned local evaluation must never be described as universally authoritative",
    ):
        assert required in text
