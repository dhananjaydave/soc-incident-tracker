from tracker.rule_catalog import RULE_CATALOG, guess_sop_from_title, lookup_catalog_entry


def test_catalog_has_substantial_coverage():
    assert len(RULE_CATALOG) > 50


def test_every_entry_has_required_fields():
    for entry in RULE_CATALOG:
        assert entry["sop"].startswith("SOP-")
        assert entry["title"]
        assert entry["category"]
        assert entry["default_severity"] in ("Critical", "High", "Medium", "Low", "Info")


def test_lookup_catalog_entry_exact_match():
    entry = lookup_catalog_entry("Access - Gap-GP-VPN Password Spraying Attempts - Rule")
    assert entry is not None
    assert entry["sop"] == "SOP-01"


def test_lookup_catalog_entry_no_match_returns_none():
    assert lookup_catalog_entry("Not a real title") is None


def test_guess_sop_from_title_matches_keyword():
    assert guess_sop_from_title("New Brute Force detection on legacy VPN") == "SOP-01"
    assert guess_sop_from_title("Anomalous PingID MFA activity") == "SOP-02"


def test_guess_sop_from_title_no_match_returns_none():
    assert guess_sop_from_title("Completely unrelated gibberish") is None
