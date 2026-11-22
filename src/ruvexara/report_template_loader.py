"""Render Ruvexara findings into the HTML assessment report."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape


# This file and the 'template' directory should be in the same project folder.
BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
TEMPLATE_NAME = "work-template.html"

# The current Ruvexara.py header describes the scanner as v2.
# Update this constant when you assign a formal release version.
RUVEXARA_VERSION = "2"

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_META = {
    "HIGH": {
        "label": "High",
        "key": "high",
        "bg_class": "bg-high",
        "stroke": "var(--sev-high)",
        "short": "H",
    },
    "MEDIUM": {
        "label": "Medium",
        "key": "medium",
        "bg_class": "bg-medium",
        "stroke": "var(--sev-medium)",
        "short": "M",
    },
    "LOW": {
        "label": "Low",
        "key": "low",
        "bg_class": "bg-low",
        "stroke": "var(--sev-low)",
        "short": "L",
    },
    "INFO": {
        "label": "Informational",
        "key": "info",
        "bg_class": "bg-info",
        "stroke": "var(--sev-info)",
        "short": "I",
    },
}


def _mask_secret(value: Any) -> str:
    """Mask a detected secret before placing it in the HTML report."""
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "••••••"
    return f"{text[:4]}...{text[-3:]}"


def _location_fields(where: Any) -> tuple[str, str, str]:
    """Return (display text, full text, safe clickable URL) for a finding location."""
    full = str(where or "")
    if not full:
        return "—", "", ""

    parsed = urlparse(full)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        display = parsed.path or "/"
        if parsed.query:
            display += f"?{parsed.query}"
        return display, full, full

    # Locations such as 'inline script #1' are labels, not hyperlinks.
    return full, full, ""


# def _normalize_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
#     """Validate, sort and enrich the scanner's five-field finding records."""
#     prepared: list[dict[str, Any]] = []

#     for original in findings:
#         severity = str(original.get("severity", "INFO")).upper()
#         if severity not in SEVERITY_META:
#             raise ValueError(
#                 f"Unsupported finding severity {severity!r}. "
#                 f"Expected one of: {', '.join(SEVERITY_META)}."
#             )

#         category = str(original.get("category") or "Uncategorized")
#         title = str(original.get("title") or "Untitled finding")

def _normalize_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prepare scanner findings for the HTML template."""

    prepared = []

    for index, original in enumerate(findings, start=1):
        severity = str(original.get("severity", "INFO")).upper()

        if severity not in SEVERITY_META:
            raise ValueError(f"Unsupported severity: {severity}")

        category = str(original.get("category") or "Uncategorized")
        title = str(original.get("title") or "Untitled finding")
        where = str(original.get("where") or "")
        detail = str(original.get("detail") or "")

        where_display, where_full, where_href = _location_fields(where)

        severity_meta = SEVERITY_META[severity]

        prepared.append({
            "finding_id": f"F-{index:02d}",
            "dom_id": f"finding-{index:02d}",
            "severity": severity,
            "severity_css": severity_meta["key"],
            "severity_label": severity_meta["label"],
            "category": category,
            "title": title,
            "where": where_full,
            "where_display": where_display,
            "where_href": where_href,
            "detail": detail,
        })

    prepared.sort(
        key=lambda finding: (
            SEVERITY_ORDER[finding["severity"]],
            finding["category"].lower(),
            finding["title"].lower(),
        )
    )

    return prepared


def write_html_report(
    output_path: str | Path,
    target: str,
    findings: Iterable[dict[str, Any]],
    authenticated: bool = False,
    scan_options: dict[str, Any] | None = None,
) -> Path:
    """Generate a complete HTML security report using Jinja2."""

    # --------------------------------------------------
    # 1. Prepare report data
    # --------------------------------------------------

    prepared_findings = _normalize_findings(findings)

    counts = {
        severity: sum(
            1 for finding in prepared_findings
            if finding["severity"] == severity
        )
        for severity in SEVERITY_ORDER
    }

    total_findings = len(prepared_findings)
    non_info_findings = total_findings - counts["INFO"]

    target_host = urlparse(target).netloc or target

    scanned_at = datetime.now().astimezone()

    scanned_iso = scanned_at.isoformat(timespec="seconds")
    scanned_display = scanned_at.strftime("%d %b %Y, %H:%M")

    scan_type = "Authenticated" if authenticated else "Anonymous"

    scan_options = scan_options or {}

    scan_options = {
        "delay": scan_options.get("delay", 0.3),
        "depth": scan_options.get("depth", 1),
        "external": scan_options.get("external", False),
    }

    # --------------------------------------------------
    # 2. Severity distribution
    # --------------------------------------------------

    severity_distribution = []

    cumulative_percent = 0

    for severity, meta in SEVERITY_META.items():

        count = counts[severity]

        percent_value = (
            count / total_findings * 100
            if total_findings else 0
        )

        percent = round(percent_value, 2)

        severity_distribution.append({
            "label": meta["label"],
            "key": meta["key"],
            "bg_class": meta["bg_class"],
            "stroke_var": meta["stroke"],
            "count": count,
            "percent": percent,
            "percent_value": percent_value,
            "remaining_percent": round(100 - percent_value, 2),
            "dash_offset": round(25 - cumulative_percent, 2),
            "percent_label": f"{percent:.1f}%",
        })

        cumulative_percent += percent_value

    # --------------------------------------------------
    # 3. Category chart
    # --------------------------------------------------

    category_counts = Counter(
        finding["category"]
        for finding in prepared_findings
    )

    category_bars = []

    for category, total in category_counts.most_common():

        category_findings = [
            finding for finding in prepared_findings
            if finding["category"] == category
        ]

        segments = []

        for severity, meta in SEVERITY_META.items():

            count = sum(
                1 for finding in category_findings
                if finding["severity"] == severity
            )

            if count:
                segments.append({
                    "bg_class": meta["bg_class"],
                    "percent": round(count / total * 100, 2),
                })

        category_bars.append({
            "name": category,
            "total": total,
            "segments": segments,
        })

    # --------------------------------------------------
    # 4. Risk rating and executive summary
    # --------------------------------------------------

    if counts["HIGH"]:
        risk_label = "High"
        risk_css = "bg-high"
        callout_class = "callout--failed"
        callout_title = "High-priority findings require attention."

    elif counts["MEDIUM"]:
        risk_label = "Moderate"
        risk_css = "bg-medium"
        callout_class = ""
        callout_title = "Medium-priority findings require review."

    elif counts["LOW"]:
        risk_label = "Low"
        risk_css = "bg-low"
        callout_class = "callout--passed"
        callout_title = "Only low-priority findings were recorded."

    else:
        risk_label = "No significant findings"
        risk_css = "dot-none"
        callout_class = "callout--passed"
        callout_title = "No high, medium or low findings recorded."

    priority_findings = [
        finding for finding in prepared_findings
        if finding["severity"] in ("HIGH", "MEDIUM", "LOW")
    ][:5]

    detailed_findings = [
        finding for finding in prepared_findings
        if finding["severity"] != "INFO"
    ]

    checks_with_findings = len(category_counts)

    # --------------------------------------------------
    # 5. Load the Jinja2 template
    # --------------------------------------------------

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
    )

    template = env.get_template(TEMPLATE_NAME)

    # --------------------------------------------------
    # 6. Render the HTML report
    # --------------------------------------------------

    html = template.render(
        target=target,
        target_host=target_host,
        tool_version=RUVEXARA_VERSION,
        scan_type=scan_type,

        scanned_iso=scanned_iso,
        scanned_display=scanned_display,

        scan_options=scan_options,

        findings=prepared_findings,
        detailed_findings=detailed_findings,
        priority_findings=priority_findings,

        counts=counts,
        total_findings=total_findings,
        non_info_findings=non_info_findings,

        severity_distribution=severity_distribution,
        category_bars=category_bars,

        risk_label=risk_label,
        risk_css=risk_css,

        callout_class=callout_class,
        callout_title=callout_title,

        checks_with_findings=checks_with_findings,
    )

    # --------------------------------------------------
    # 7. Save the generated HTML
    # --------------------------------------------------

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        html,
        encoding="utf-8",
    )

    print(f"[+] HTML report saved to {output_path}")

    return output_path
