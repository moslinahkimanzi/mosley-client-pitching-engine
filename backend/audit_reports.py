"""Minimal, dependency-free PDF renderer for stored MCAS website audit reports."""
from __future__ import annotations

from datetime import datetime
from textwrap import wrap
from urllib.parse import urlparse


PAGE_W = 595
PAGE_H = 842
MARGIN = 46
CONTENT_W = PAGE_W - 2 * MARGIN

CLASS_LABELS = {
    "detected_defect": "DETECTED DEFECT",
    "potential_risk": "POTENTIAL RISK",
    "recommendation": "RECOMMENDATION",
    "unverified_observation": "UNVERIFIED OBSERVATION",
}
CLASS_ORDER = (
    "detected_defect",
    "potential_risk",
    "recommendation",
    "unverified_observation",
)
COLORS = {
    "navy": (0.08, 0.13, 0.22),
    "teal": (0.02, 0.55, 0.55),
    "ink": (0.12, 0.17, 0.23),
    "muted": (0.38, 0.43, 0.49),
    "line": (0.86, 0.89, 0.92),
    "pale": (0.95, 0.97, 0.98),
    "white": (1, 1, 1),
    "red": (0.72, 0.19, 0.20),
    "amber": (0.72, 0.44, 0.08),
    "green": (0.10, 0.45, 0.33),
}


def _safe(value) -> str:
    """PDF standard fonts use WinAnsi; replace unsupported glyphs safely."""
    raw = str(value if value is not None else "")
    raw = raw.replace("\u2022", "-").replace("\u2013", "-").replace("\u2014", "-")
    raw = raw.replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
    raw = raw.replace("\u00a0", " ")
    return raw.encode("cp1252", "replace").decode("cp1252")


def _pdf_literal(value: str) -> str:
    return _safe(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class _Canvas:
    def __init__(self):
        self.pages: list[list[str]] = []
        self.ops: list[str] = []
        self.y = 0
        self.page_number = 0
        self.new_page()

    def _color(self, color, stroke=False):
        r, g, b = color
        return f"{r:.3f} {g:.3f} {b:.3f} {'RG' if stroke else 'rg'}"

    def rect(self, x, top, width, height, color):
        bottom = PAGE_H - top - height
        self.ops.append(f"{self._color(color)} {x:.2f} {bottom:.2f} {width:.2f} {height:.2f} re f")

    def line(self, x1, top1, x2, top2, color=None, width=0.7):
        color = color or COLORS["line"]
        self.ops.append(
            f"{self._color(color, True)} {width:.2f} w {x1:.2f} {PAGE_H-top1:.2f} m "
            f"{x2:.2f} {PAGE_H-top2:.2f} l S"
        )

    def text(self, x, top, value, size=9, bold=False, color=None):
        color = color or COLORS["ink"]
        font = "F2" if bold else "F1"
        bottom = PAGE_H - top - size
        self.ops.append(
            f"{self._color(color)} BT /{font} {size:.2f} Tf 1 0 0 1 "
            f"{x:.2f} {bottom:.2f} Tm ({_pdf_literal(value)}) Tj ET"
        )

    def new_page(self):
        if self.ops:
            self.pages.append(self.ops)
        self.ops = []
        self.page_number += 1
        self.rect(0, 0, PAGE_W, 8, COLORS["teal"])
        self.text(MARGIN, 27, "MCAS  |  WEBSITE TECHNICAL AUDIT", 8, True, COLORS["muted"])
        self.line(MARGIN, 43, PAGE_W - MARGIN, 43)
        self.y = 62

    def ensure(self, height):
        if self.y + height > PAGE_H - 62:
            self.new_page()

    def heading(self, title, level=1):
        size = 16 if level == 1 else 11
        self.ensure(size + 18)
        self.text(MARGIN, self.y, title, size, True, COLORS["navy"])
        self.y += size + 8
        self.line(MARGIN, self.y, PAGE_W - MARGIN, self.y, COLORS["teal"], 1.0 if level == 1 else 0.5)
        self.y += 10

    def paragraph(self, value, size=9, color=None, indent=0, gap=3, max_width=CONTENT_W):
        text = _safe(value).strip()
        if not text:
            return
        char_width = max(24, int(max_width / (size * 0.51)))
        lines = []
        for raw_line in text.splitlines() or [text]:
            lines.extend(wrap(raw_line, width=char_width, break_long_words=True, break_on_hyphens=True) or [""])
        line_height = size + 4
        self.ensure(len(lines) * line_height + gap)
        for line in lines:
            self.text(MARGIN + indent, self.y, line, size, False, color or COLORS["ink"])
            self.y += line_height
        self.y += gap

    def bullet(self, value, size=8.5):
        self.paragraph("- " + str(value), size=size, indent=9, gap=2)

    def card(self, title, meta, description, evidence, pages, recommendation, classification, severity):
        label = CLASS_LABELS.get(classification, CLASS_LABELS[CLASS_UNVERIFIED])
        severity_color = COLORS["red"] if severity == "high" else COLORS["amber"] if severity == "medium" else COLORS["muted"]
        estimated = 32 + 4 * (len(wrap(_safe(description), 92)) + len(wrap(_safe(recommendation), 92))) + 30
        self.ensure(min(max(estimated, 90), 300))
        self.rect(MARGIN, self.y, CONTENT_W, 24, COLORS["pale"])
        self.text(MARGIN + 9, self.y + 6, title[:120], 9.4, True, COLORS["navy"])
        self.text(PAGE_W - MARGIN - 125, self.y + 7, severity.upper() + "  |  " + label, 6.6, True, severity_color)
        self.y += 31
        self.paragraph(description, 8.4, gap=2)
        if evidence:
            self.paragraph("Evidence: " + str(evidence), 7.7, COLORS["muted"], gap=2)
        if pages:
            page_text = ", ".join(pages[:5])
            if len(pages) > 5:
                page_text += f" and {len(pages)-5} more page(s)"
            self.paragraph("Affected pages: " + page_text, 7.3, COLORS["muted"], gap=2)
        self.paragraph("Suggested action: " + str(recommendation), 8.2, gap=6)
        self.line(MARGIN, self.y, PAGE_W - MARGIN, self.y)
        self.y += 9

    def finish(self):
        self.pages.append(self.ops)
        total = len(self.pages)
        for number, page_ops in enumerate(self.pages, 1):
            page_ops.append(
                f"{self._color(COLORS['line'], True)} 0.5 w {MARGIN} 48 m {PAGE_W-MARGIN} 48 l S"
            )
            page_ops.append(
                f"{self._color(COLORS['muted'])} BT /F1 7 Tf 1 0 0 1 {MARGIN} 31 Tm "
                f"(MCAS - bounded public website audit - Page {number} of {total}) Tj ET"
            )
        return _assemble_pdf(self.pages)


def _assemble_pdf(pages: list[list[str]]) -> bytes:
    objects: list[bytes | None] = [None, None, None]
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    objects.insert(2, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    # Object indexes now: 1 catalog, 2 pages placeholder, 3 Helvetica, 4 Helvetica-Bold.
    page_refs = []
    for ops in pages:
        stream = ("\n".join(ops) + "\n").encode("cp1252", "replace")
        content_id = len(objects) + 1
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"endstream"
        )
        page_id = len(objects) + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
            f"/Contents {content_id} 0 R >>".encode()
        )
        page_refs.append(f"{page_id} 0 R")
    objects[1] = (
        f"<< /Type /Pages /Count {len(page_refs)} /Kids [{' '.join(page_refs)}] >>".encode()
    )
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out.extend(f"{index} 0 obj\n".encode())
        out.extend(obj or b"")
        out.extend(b"\nendobj\n")
    xref_offset = len(out)
    out.extend(f"xref\n0 {len(objects)+1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(
        f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode()
    )
    return bytes(out)


def build_audit_pdf(report: dict) -> bytes:
    """Build a client-ready report from one persisted audit payload."""
    canvas = _Canvas()
    summary = report.get("summary") or {}
    website = str(report.get("url") or "Website not supplied")
    host = urlparse(website).hostname or website
    checked_at = str(report.get("checked_at") or report.get("created_at") or "Not recorded")
    findings = report.get("findings") or []
    opportunities = report.get("recommendations") or []

    canvas.rect(MARGIN, canvas.y, CONTENT_W, 102, COLORS["navy"])
    canvas.text(MARGIN + 16, canvas.y + 17, "WEBSITE TECHNICAL AUDIT", 20, True, COLORS["white"])
    canvas.text(MARGIN + 16, canvas.y + 47, host[:70], 11, True, COLORS["white"])
    canvas.text(MARGIN + 16, canvas.y + 68, website[:88], 7.5, False, COLORS["white"])
    canvas.text(MARGIN + 16, canvas.y + 84, "Prepared by MCAS  |  Checked " + checked_at[:40], 7, False, COLORS["white"])
    canvas.y += 116

    score = summary.get("health_score", "Not scored")
    canvas.rect(MARGIN, canvas.y, 145, 65, COLORS["pale"])
    canvas.text(MARGIN + 10, canvas.y + 10, "HEALTH INDICATOR", 7, True, COLORS["muted"])
    canvas.text(MARGIN + 10, canvas.y + 26, f"{score}/100" if isinstance(score, int) else str(score), 19, True, COLORS["navy"])
    canvas.text(MARGIN + 10, canvas.y + 49, "Unique issues only", 7, False, COLORS["muted"])
    stats = [
        ("DEFECTS", summary.get("detected_defects", 0), COLORS["red"]),
        ("RISKS", summary.get("potential_risks", 0), COLORS["amber"]),
        ("UNVERIFIED", summary.get("unverified_observations", 0), COLORS["muted"]),
    ]
    for index, (label, value, color) in enumerate(stats):
        x = MARGIN + 155 + index * 104
        canvas.rect(x, canvas.y, 96, 65, COLORS["pale"])
        canvas.text(x + 8, canvas.y + 10, label, 6.6, True, COLORS["muted"])
        canvas.text(x + 8, canvas.y + 28, str(value), 18, True, color)
    canvas.y += 78
    canvas.paragraph(
        f"Scope: {report.get('pages_checked', 0)} page(s) checked. "
        f"{summary.get('unique_findings', summary.get('total', len(findings)))} unique issue(s); "
        f"{summary.get('page_occurrences', 0)} page occurrence(s). "
        "Repeated issues across pages are grouped once for scoring, with affected URLs retained.",
        size=8.2,
    )
    canvas.paragraph(
        str(report.get("score_disclaimer") or
            "The health score is a prioritisation indicator for this bounded audit, not a security certification."),
        size=7.8, color=COLORS["muted"],
    )

    if findings:
        canvas.heading("Technical findings")
        for classification in CLASS_ORDER:
            group = [item for item in findings if item.get("classification") == classification]
            if not group:
                continue
            canvas.heading(CLASS_LABELS[classification].replace("_", " ").title(), level=2)
            for item in group:
                evidence_entries = item.get("evidence_by_page") or []
                evidence = "; ".join(
                    f"{entry.get('url')}: {entry.get('detail')}"
                    for entry in evidence_entries[:4]
                )
                canvas.card(
                    item.get("title") or item.get("code") or "Finding",
                    "",
                    item.get("description") or "",
                    evidence or item.get("evidence") or "",
                    item.get("affected_pages") or ([item.get("url")] if item.get("url") else []),
                    item.get("recommendation") or "Review with the website owner.",
                    classification,
                    item.get("severity") or "info",
                )
    else:
        canvas.heading("Technical findings")
        canvas.paragraph("No findings were produced by the bounded checks performed. This does not prove that untested areas are defect-free.")

    canvas.heading("Website improvement opportunities")
    canvas.paragraph(
        "These are suggested service opportunities derived from the findings below. Confirm business goals, existing platform constraints and project scope with the website owner before quoting or making changes.",
        size=8,
    )
    for opportunity in opportunities:
        canvas.ensure(100)
        canvas.text(MARGIN, canvas.y, opportunity.get("title", "Improvement opportunity"), 10, True, COLORS["teal"])
        canvas.y += 16
        canvas.paragraph(opportunity.get("description", ""), size=8.3)
        for item in opportunity.get("recommended_scope") or []:
            canvas.bullet(item)
        if opportunity.get("basis"):
            canvas.paragraph("Basis: " + opportunity["basis"], size=7.4, color=COLORS["muted"])
        canvas.y += 5

    canvas.heading("Pages inspected")
    for page in report.get("pages") or []:
        status = "HTTP " + str(page.get("http_status")) if page.get("http_status") is not None else "Not confirmed"
        title = str(page.get("title") or "No page title detected")[:90]
        response = page.get("response_time_ms")
        response_text = (str(round(float(response))) + " ms") if isinstance(response, (int, float)) else "Not measured"
        canvas.paragraph(f"{page.get('url', 'URL not recorded')}  |  {status}  |  {response_text}  |  {title}", size=7.5, gap=2)

    canvas.heading("Method, limitations and verification")
    canvas.paragraph(str(report.get("scope_note") or "Bounded public-page audit only."), size=8)
    for limitation in report.get("limitations") or []:
        canvas.bullet(limitation, size=7.8)
    canvas.paragraph(
        "Client-facing use: this report records what the automated checks observed at the stated time. "
        "Dynamic content, authenticated pages, real user experience, accessibility conformance, application security and business requirements require separate verification. "
        "Do not describe an unverified observation or missing hardening header as a confirmed vulnerability.",
        size=8.1,
    )
    return canvas.finish()


def audit_pdf_filename(report: dict) -> str:
    host = urlparse(str(report.get("url") or "")).hostname or "website"
    host = "".join(char if char.isalnum() or char in ".-" else "-" for char in host)[:80]
    try:
        checked = datetime.fromisoformat(str(report.get("checked_at") or "").replace("Z", "+00:00"))
        date = checked.strftime("%Y%m%d")
    except ValueError:
        date = "report"
    return f"mcas-audit-{host}-{date}.pdf"
