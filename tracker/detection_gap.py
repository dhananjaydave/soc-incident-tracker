"""Detection Gap Analyzer: which of the 55 curated MITRE ATT&CK
techniques have no Rule Book entry covering them yet. Not a claim about
real detection coverage (that depends on actual SIEM rules, which this
app doesn't see) - just a gap check between the knowledge base and the
Rule Book, to show where to write the next rule.
"""

from __future__ import annotations

from .mitre_knowledge import MITRE_TECHNIQUES, list_techniques
from .rule_book import all_mapped_mitre_technique_ids


def compute_detection_gap() -> dict:
    covered_ids = all_mapped_mitre_technique_ids() & set(MITRE_TECHNIQUES.keys())
    all_ids = set(MITRE_TECHNIQUES.keys())
    uncovered_ids = sorted(all_ids - covered_ids)

    technique_lookup = {t["id"]: t for t in list_techniques()}
    uncovered = [technique_lookup[tid] for tid in uncovered_ids]

    total = len(all_ids)
    covered_count = len(covered_ids)
    percent_covered = round((covered_count / total) * 100) if total else 0

    return {
        "covered_count": covered_count,
        "total_count": total,
        "percent_covered": percent_covered,
        "uncovered": uncovered,
    }
