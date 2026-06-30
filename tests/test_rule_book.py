import tempfile
from pathlib import Path

import pytest

from tracker.db import TrackerDB
from tracker.rule_book import (
    CONFIDENCE_SCALE,
    RULE_BOOK,
    SOP_CATEGORIES,
    SUSPICIOUS_IP_GUIDE,
    all_mapped_mitre_technique_ids,
    seed_rule_book,
)


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        yield TrackerDB(db_path=str(Path(tmp) / "test.db"))


def test_eight_sop_categories_defined():
    assert len(SOP_CATEGORIES) == 8
    ids = {c["id"] for c in SOP_CATEGORIES}
    assert ids == {"RB-01", "RB-02", "RB-03", "RB-04", "RB-05", "RB-06", "RB-07", "RB-08"}


def test_nine_real_rules_defined():
    assert len(RULE_BOOK) == 9
    expected = {
        "GP-VPN Brute Force Attempts", "Password Spraying Attempts", "Azure Risky Sign-in",
        "PingID MFA Spamming", "CrowdStrike High Alert", "Defender High Alert", "O365 Phishing Alert",
        "DDoS Attack Detected", "Major Incident",
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


def test_every_rule_has_description_template_with_five_ws():
    for alert_type, rule in RULE_BOOK.items():
        template = rule.get("description_template")
        assert template, f"{alert_type} missing description_template"
        assert set(template.keys()) == {"who", "what", "when", "where", "why"}, alert_type


def test_every_rule_has_default_priority():
    for alert_type, rule in RULE_BOOK.items():
        assert rule.get("default_priority") in ("low", "medium", "high"), alert_type


def test_every_rule_has_detection_engineering():
    required = {"name", "type", "data_sources", "logic", "confidence_guidance"}
    for alert_type, rule in RULE_BOOK.items():
        de = rule.get("detection_engineering")
        assert de, f"{alert_type} missing detection_engineering"
        assert required.issubset(de.keys()), alert_type


def test_every_rule_has_splunk_queries_list():
    for alert_type, rule in RULE_BOOK.items():
        queries = rule.get("splunk_queries")
        assert queries, f"{alert_type} missing splunk_queries"
        for q in queries:
            assert "name" in q and "query" in q


def test_every_rule_has_ip_check_guide():
    for alert_type, rule in RULE_BOOK.items():
        assert rule.get("ip_check_guide"), f"{alert_type} missing ip_check_guide"


def test_every_rule_has_description_sections():
    required = {"executive_summary", "findings", "impact_assessment", "actions_taken", "recommendations"}
    for alert_type, rule in RULE_BOOK.items():
        sections = rule.get("description_sections")
        assert sections, f"{alert_type} missing description_sections"
        assert required.issubset(sections.keys()), alert_type


def test_confidence_scale_has_four_bands():
    assert len(CONFIDENCE_SCALE) == 4
    ranges = {c["range"] for c in CONFIDENCE_SCALE}
    assert "90-100%" in ranges
    assert "Below 50%" in ranges


def test_suspicious_ip_guide_has_steps():
    assert SUSPICIOUS_IP_GUIDE["steps"]
    assert len(SUSPICIOUS_IP_GUIDE["steps"]) >= 3


async def test_seed_rule_book_populates_db(db):
    await seed_rule_book(db)
    sops = await db.list_sops()
    assert len(sops) == 9


async def test_seed_rule_book_sets_category_and_structured(db):
    await seed_rule_book(db)
    sop = await db.get_sop("Azure Risky Sign-in")
    assert sop["category"] == "RB-03: Risky Sign-in / Identity Compromise"
    assert "Entra ID" in sop["structured"]["investigation_steps"][0]


async def test_seed_rule_book_includes_common_titles(db):
    await seed_rule_book(db)
    sop = await db.get_sop("Azure Risky Sign-in")
    assert "Impossible travel sign-in detected" in sop["structured"]["common_titles"]


async def test_seed_rule_book_includes_mitre_techniques(db):
    await seed_rule_book(db)
    sop = await db.get_sop("Azure Risky Sign-in")
    assert "T1078" in sop["structured"]["mitre_techniques"]


async def test_seed_rule_book_includes_default_priority(db):
    await seed_rule_book(db)
    sop = await db.get_sop("DDoS Attack Detected")
    assert sop["structured"]["default_priority"] == "high"


async def test_seed_rule_book_includes_detection_engineering(db):
    await seed_rule_book(db)
    sop = await db.get_sop("DDoS Attack Detected")
    assert sop["structured"]["detection_engineering"]["name"]


async def test_seed_rule_book_includes_alert_description(db):
    await seed_rule_book(db)
    sop = await db.get_sop("DDoS Attack Detected")
    assert "denial-of-service" in sop["structured"]["alert_description"].lower() or "overwhelming" in sop["structured"]["alert_description"].lower()


async def test_seed_rule_book_includes_splunk_queries(db):
    await seed_rule_book(db)
    sop = await db.get_sop("DDoS Attack Detected")
    assert len(sop["structured"]["splunk_queries"]) > 0


async def test_seed_rule_book_includes_ddos_rule(db):
    await seed_rule_book(db)
    sop = await db.get_sop("DDoS Attack Detected")
    assert sop is not None
    assert sop["category"] == "RB-07: DDoS / Availability"


def test_all_mapped_mitre_technique_ids_nonempty():
    ids = all_mapped_mitre_technique_ids()
    assert "T1110" in ids
    assert "T1621" in ids
    assert "T1499" in ids
    assert len(ids) > 0


def test_every_rule_has_at_least_one_mitre_technique_except_major_incident():
    # Major Incident is a severity-escalation classification (anything can
    # be a major incident), not a specific detection - deliberately has no
    # fixed MITRE mapping.
    for alert_type, rule in RULE_BOOK.items():
        if alert_type == "Major Incident":
            continue
        assert rule.get("mitre_techniques"), f"{alert_type} has no MITRE technique mapping"


async def test_seed_rule_book_does_not_overwrite_existing_customization(db):
    await db.upsert_sop("GP-VPN Brute Force Attempts", "My custom override steps")
    await seed_rule_book(db)
    sop = await db.get_sop("GP-VPN Brute Force Attempts")
    assert sop["steps"] == "My custom override steps"
