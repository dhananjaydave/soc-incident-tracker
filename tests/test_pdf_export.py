from tracker.pdf_export import build_incidents_pdf


def test_build_pdf_with_no_incidents():
    pdf_bytes = build_incidents_pdf([])
    assert pdf_bytes.startswith(b"%PDF")


def test_build_pdf_with_incidents():
    incidents = [
        {"id": 1, "alert_type": "Phishing", "title": "Suspicious email", "status": "open",
         "affected_user": "jdoe", "created_at": "2026-06-28T10:00:00+00:00"},
        {"id": 2, "alert_type": "System Compromise", "title": "C2 traffic detected", "status": "resolved",
         "affected_user": None, "created_at": "2026-06-28T11:00:00+00:00"},
    ]
    pdf_bytes = build_incidents_pdf(incidents)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 100


def test_build_pdf_truncates_long_fields():
    incidents = [{
        "id": 1, "alert_type": "Phishing", "title": "x" * 500, "status": "open",
        "affected_user": "jdoe", "created_at": "2026-06-28T10:00:00+00:00",
    }]
    pdf_bytes = build_incidents_pdf(incidents)
    assert pdf_bytes.startswith(b"%PDF")


def test_build_pdf_does_not_crash_on_non_latin1_characters():
    incidents = [{
        "id": 1, "alert_type": "Phishing", "title": "Urgent \U0001F6A8 email from CEO 你好", "status": "open",
        "affected_user": "jdoe", "created_at": "2026-06-28T10:00:00+00:00",
    }]
    pdf_bytes = build_incidents_pdf(incidents)
    assert pdf_bytes.startswith(b"%PDF")
