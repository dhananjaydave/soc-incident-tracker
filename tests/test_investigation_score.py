from tracker.investigation_score import compute_investigation_score

SOP_WITH_CHECKLIST = {
    "structured": {
        "closure_checklist": [
            "Disposition reason recorded.",
            "Stakeholder contacted and response recorded.",
            "Investigation documented in notes.",
            "Evidence attached.",
        ],
    },
}


def test_no_sop_returns_empty_checklist():
    result = compute_investigation_score({"disposition_reason": None, "awaiting_stakeholder_reply": 0}, None, [])
    assert result["items"] == []
    assert result["percent_done"] == 0
    assert result["total_count"] == 0


def test_sop_without_structured_returns_empty_checklist():
    result = compute_investigation_score({"disposition_reason": None, "awaiting_stakeholder_reply": 0}, {"structured": None}, [])
    assert result["items"] == []


def test_disposition_reason_item_marked_done_when_present():
    incident = {"disposition_reason": "Confirmed benign", "awaiting_stakeholder_reply": 0}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [])
    reason_item = next(i for i in result["items"] if "reason" in i["item"].lower())
    assert reason_item["status"] == "done"


def test_disposition_reason_item_needs_review_when_absent():
    incident = {"disposition_reason": None, "awaiting_stakeholder_reply": 0}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [])
    reason_item = next(i for i in result["items"] if "reason" in i["item"].lower())
    assert reason_item["status"] == "needs_review"


def test_stakeholder_item_done_when_not_awaiting():
    incident = {"disposition_reason": None, "awaiting_stakeholder_reply": 0}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [])
    stakeholder_item = next(i for i in result["items"] if "stakeholder" in i["item"].lower())
    assert stakeholder_item["status"] == "done"


def test_stakeholder_item_needs_review_when_awaiting():
    incident = {"disposition_reason": None, "awaiting_stakeholder_reply": 1}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [])
    stakeholder_item = next(i for i in result["items"] if "stakeholder" in i["item"].lower())
    assert stakeholder_item["status"] == "needs_review"


def test_investigation_documented_item_done_when_notes_exist():
    incident = {"disposition_reason": None, "awaiting_stakeholder_reply": 0}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [{"note": "checked logs"}])
    doc_item = next(i for i in result["items"] if "documented" in i["item"].lower())
    assert doc_item["status"] == "done"


def test_unmappable_item_always_needs_review():
    incident = {"disposition_reason": "x", "awaiting_stakeholder_reply": 0}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [{"note": "x"}])
    evidence_item = next(i for i in result["items"] if "evidence" in i["item"].lower())
    assert evidence_item["status"] == "needs_review"


def test_percent_done_computed_correctly():
    incident = {"disposition_reason": "x", "awaiting_stakeholder_reply": 0}
    result = compute_investigation_score(incident, SOP_WITH_CHECKLIST, [{"note": "x"}])
    # 3 of 4 items done (reason, stakeholder, documented) - evidence stays needs_review
    assert result["done_count"] == 3
    assert result["total_count"] == 4
    assert result["percent_done"] == 75


def test_fully_done_ticket_is_100_percent():
    incident = {"disposition_reason": "x", "awaiting_stakeholder_reply": 0}
    sop = {"structured": {"closure_checklist": ["Disposition reason recorded."]}}
    result = compute_investigation_score(incident, sop, [])
    assert result["percent_done"] == 100
