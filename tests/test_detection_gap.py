from tracker.detection_gap import compute_detection_gap
from tracker.mitre_knowledge import MITRE_TECHNIQUES
from tracker.rule_book import all_mapped_mitre_technique_ids


def test_compute_detection_gap_totals_match_full_technique_list():
    result = compute_detection_gap()
    assert result["total_count"] == len(MITRE_TECHNIQUES)


def test_compute_detection_gap_covered_count_matches_rule_book():
    result = compute_detection_gap()
    expected = len(all_mapped_mitre_technique_ids() & set(MITRE_TECHNIQUES.keys()))
    assert result["covered_count"] == expected


def test_compute_detection_gap_percent_is_consistent():
    result = compute_detection_gap()
    expected_percent = round((result["covered_count"] / result["total_count"]) * 100)
    assert result["percent_covered"] == expected_percent


def test_compute_detection_gap_uncovered_excludes_mapped_techniques():
    result = compute_detection_gap()
    uncovered_ids = {t["id"] for t in result["uncovered"]}
    mapped_ids = all_mapped_mitre_technique_ids()
    assert uncovered_ids.isdisjoint(mapped_ids)


def test_compute_detection_gap_uncovered_count_matches():
    result = compute_detection_gap()
    assert len(result["uncovered"]) == result["total_count"] - result["covered_count"]


def test_compute_detection_gap_uncovered_entries_have_full_technique_data():
    result = compute_detection_gap()
    if result["uncovered"]:
        sample = result["uncovered"][0]
        assert "name" in sample
        assert "tactic" in sample
