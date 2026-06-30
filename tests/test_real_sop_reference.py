from tracker.real_sop_reference import REAL_SOP_REFERENCE, get_sop_reference


def test_three_sops_loaded_so_far():
    assert set(REAL_SOP_REFERENCE.keys()) == {"SOP-01", "SOP-02", "SOP-03"}


def test_every_loaded_sop_has_required_fields():
    for sop_id, entry in REAL_SOP_REFERENCE.items():
        assert entry["title"]
        assert entry["l1_escalation_triggers"]
        assert entry["l3_escalation_triggers"]
        assert set(entry["verdict_guidance"].keys()) == {
            "Malicious", "Unresolved-suspicious", "Policy violation", "Authorized", "Benign-other",
        }
        assert entry["servicenow_routing"]
        assert entry["closure_examples"]


def test_get_sop_reference_returns_entry():
    ref = get_sop_reference("SOP-01")
    assert ref is not None
    assert "GP-VPN Password Spraying" in ref["rules_covered"]


def test_get_sop_reference_returns_none_for_not_yet_added_sop():
    assert get_sop_reference("SOP-09") is None
