from tracker.mitre_knowledge import MITRE_TECHNIQUES, get_technique, list_techniques


def test_get_technique_found():
    technique = get_technique("T1055")
    assert technique["name"] == "Process Injection"


def test_get_technique_case_insensitive():
    assert get_technique("t1055") is not None


def test_get_technique_strips_whitespace():
    assert get_technique(" T1055 ") is not None


def test_get_technique_not_found_returns_none():
    assert get_technique("T9999") is None


def test_list_techniques_returns_all():
    techniques = list_techniques()
    assert len(techniques) == len(MITRE_TECHNIQUES)


def test_list_techniques_sorted_by_id():
    techniques = list_techniques()
    ids = [t["id"] for t in techniques]
    assert ids == sorted(ids)


def test_every_technique_has_required_fields():
    required = {"name", "tactic", "what_it_is", "looks_like_in_practice", "common_false_positive", "next_step"}
    for tid, data in MITRE_TECHNIQUES.items():
        missing = required - set(data.keys())
        assert not missing, f"{tid} missing fields: {missing}"


def test_every_technique_id_matches_mitre_format():
    import re
    for tid in MITRE_TECHNIQUES:
        assert re.match(r"^T\d{4}$", tid), f"{tid} doesn't match expected MITRE ID format"
