import tempfile
from pathlib import Path

import pytest

from tracker.db import TrackerDB
from tracker.rule_book import RULE_BOOK, SOP_CATEGORIES, seed_rule_book


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


def test_six_sop_categories_defined():
    assert len(SOP_CATEGORIES) == 6
    ids = {c["id"] for c in SOP_CATEGORIES}
    assert ids == {"SOP-01", "SOP-02", "SOP-03", "SOP-04", "SOP-05", "SOP-06"}


def test_seven_real_rules_defined():
    assert len(RULE_BOOK) == 7
    expected = {
        "GP-VPN Brute Force Attempts", "Password Spraying Attempts", "Azure Risky Sign-in",
        "PingID MFA Spamming", "CrowdStrike High Alert", "Defender High Alert", "O365 Phishing Alert",
    }
    assert set(RULE_BOOK.keys()) == expected


def test_every_rule_has_full_structured_content():
    required_keys = {
        "investigation_steps", "required_fields", "escalation_criteria", "splunk_query_hint",
        "containment_actions", "closure_checklist", "false_positive_indicators",
    }
    for alert_type, rule in RULE_BOOK.items():
        assert rule["category"], f"{alert_type} missing category"
        assert rule["steps"], f"{alert_type} missing steps"
        assert required_keys.issubset(rule["structured"].keys()), f"{alert_type} missing structured fields"


async def test_seed_rule_book_populates_db(db):
    await seed_rule_book(db)
    sops = await db.list_sops()
    assert len(sops) == 7


async def test_seed_rule_book_sets_category_and_structured(db):
    await seed_rule_book(db)
    sop = await db.get_sop("Azure Risky Sign-in")
    assert sop["category"] == "SOP-03: Risky Sign-in / Identity Compromise"
    assert "Entra ID" in sop["structured"]["investigation_steps"][0]


async def test_seed_rule_book_includes_common_titles(db):
    await seed_rule_book(db)
    sop = await db.get_sop("Azure Risky Sign-in")
    assert "Impossible travel sign-in detected" in sop["structured"]["common_titles"]


async def test_seed_rule_book_does_not_overwrite_existing_customization(db):
    await db.upsert_sop("GP-VPN Brute Force Attempts", "My custom override steps")
    await seed_rule_book(db)
    sop = await db.get_sop("GP-VPN Brute Force Attempts")
    assert sop["steps"] == "My custom override steps"
