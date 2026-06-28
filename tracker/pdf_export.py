"""PDF version of the incident export - same data as the CSV export, but
formatted for a quick printed/shared shift report rather than spreadsheet
analysis.
"""

from __future__ import annotations

from fpdf import FPDF, XPos, YPos

COLUMN_WIDTHS = {
    "id": 10, "alert_type": 35, "title": 45, "status": 22, "affected_user": 25, "created_at": 30,
}


def _sanitize(text: str | None) -> str:
    # The core Helvetica font only supports latin-1 - replace anything
    # else (emoji, non-Latin scripts) rather than letting fpdf2 raise.
    text = text or ""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _truncate(text: str | None, max_chars: int) -> str:
    text = _sanitize(text)
    return text if len(text) <= max_chars else text[: max_chars - 3] + "..."


def build_incidents_pdf(incidents: list[dict]) -> bytes:
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "SOC Incident Tracker - Export", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Total incidents: {len(incidents)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 9)
    for col, width in COLUMN_WIDTHS.items():
        pdf.cell(width, 7, col.replace("_", " ").title(), border=1)
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for incident in incidents:
        pdf.cell(COLUMN_WIDTHS["id"], 7, str(incident.get("id", "")), border=1)
        pdf.cell(COLUMN_WIDTHS["alert_type"], 7, _truncate(incident.get("alert_type"), 22), border=1)
        pdf.cell(COLUMN_WIDTHS["title"], 7, _truncate(incident.get("title"), 28), border=1)
        pdf.cell(COLUMN_WIDTHS["status"], 7, _truncate(incident.get("status"), 14), border=1)
        pdf.cell(COLUMN_WIDTHS["affected_user"], 7, _truncate(incident.get("affected_user"), 16), border=1)
        pdf.cell(COLUMN_WIDTHS["created_at"], 7, _truncate(incident.get("created_at"), 19), border=1)
        pdf.ln()

    return bytes(pdf.output())
