"""PDF investigation-report generation via reportlab."""
import io
from html import escape as html_escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

SEVERITY_COLORS = {
    "Low": colors.HexColor("#2e7d32"),
    "Medium": colors.HexColor("#f9a825"),
    "High": colors.HexColor("#ef6c00"),
    "Critical": colors.HexColor("#c62828"),
}


def _text(value):
    """Escape untrusted analysis/report text for ReportLab Paragraph markup."""
    return html_escape(str(value if value is not None else ""), quote=True)


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H", parent=ss["Heading2"], textColor=colors.HexColor("#1a237e"),
                          spaceBefore=10, spaceAfter=4))
    ss.add(ParagraphStyle("Body", parent=ss["BodyText"], fontSize=9.5, leading=13))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], fontSize=8, textColor=colors.grey))
    return ss


def build_pdf(analysis: dict, report: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            title="APK Fraud Analysis Report")
    ss = _styles()
    el = []

    f = analysis.get("file", {})
    m = analysis.get("manifest", {})
    sev = analysis.get("severity", "Low")
    score = analysis.get("risk_score", 0)
    sev_color = SEVERITY_COLORS.get(sev, colors.grey)

    # --- Title ---
    el.append(Paragraph("APK Fraud Analysis Report", ss["Title"]))
    el.append(Paragraph("Generative-AI Automated Static Analysis &amp; Risk Scoring", ss["Small"]))
    el.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a237e")))
    el.append(Spacer(1, 6))

    # --- Header table: metadata + score ---
    meta = [
        ["APK Name", f.get("filename", "—"), "Risk Score", f"{score}/100"],
        ["Package", m.get("package_name", "—"), "Severity", sev],
        ["Version", m.get("version_name", "—"), "Threat", report.get("threat_assessment", "—")],
        ["Analysis", analysis.get("analysis_quality", "full").title(), "", ""],
        ["SHA256", f.get("sha256", "—"), "", ""],
        ["MD5", f.get("md5", "—"), "", ""],
    ]
    t = Table(meta, colWidths=[24 * mm, 92 * mm, 24 * mm, 38 * mm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (3, 0), (3, 1), sev_color),
        ("FONTNAME", (3, 0), (3, 1), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1fb")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef1fb")),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e0e0e0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    el.append(t)
    el.append(Spacer(1, 8))

    def section(title):
        el.append(Paragraph(title, ss["H"]))

    def bullets(items):
        for it in items or []:
            el.append(Paragraph(f"• {_text(it)}", ss["Body"]))
        if not items:
            el.append(Paragraph("None identified.", ss["Body"]))

    # --- Executive summary ---
    section("Executive Summary")
    el.append(Paragraph(_text(report.get("executive_summary", "—")), ss["Body"]))

    # --- Technical summary ---
    section("Technical Findings")
    el.append(Paragraph(_text(report.get("technical_summary", "—")), ss["Body"]))

    # --- Detected behaviours ---
    section("Detected Behaviours")
    bullets(analysis.get("detected_behaviors", []))

    # --- Attack chain ---
    if report.get("attack_chain"):
        section("Likely Attack Chain")
        for i, step in enumerate(report["attack_chain"], 1):
            el.append(Paragraph(f"{i}. {_text(step)}", ss["Body"]))

    # --- Risk score breakdown ---
    section("Risk Score Breakdown")
    rows = [["Category", "Points", "Detail"]]
    for b in analysis.get("score_breakdown", []):
        rows.append([b["category"], f"+{b['points']}", b.get("detail", "")])
    rows.append(["TOTAL", str(score), severity_band_text(sev)])
    bt = Table(rows, colWidths=[42 * mm, 18 * mm, 118 * mm])
    bt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#eef1fb")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    el.append(bt)

    # --- Technical evidence ---
    section("Technical Evidence")
    perms = [p["name"] for p in analysis.get("permissions", {}).get("dangerous", [])]
    apis = [a["api"] for a in analysis.get("apis", {}).get("suspicious_apis", [])]
    el.append(Paragraph(f"<b>Dangerous permissions:</b> {', '.join(perms) or 'none'}", ss["Body"]))
    el.append(Paragraph(f"<b>Suspicious APIs:</b> {', '.join(apis) or 'none'}", ss["Body"]))

    # --- IOCs ---
    section("Indicators of Compromise (IOCs)")
    iocs = analysis.get("iocs", {})
    for label, key in [("URLs", "urls"), ("Domains", "domains"), ("IPs", "ips"),
                       ("Telegram tokens", "telegram_tokens"), ("Hardcoded secrets", "hardcoded_secrets")]:
        vals = iocs.get(key, [])
        if vals:
            el.append(Paragraph(f"<b>{label}:</b> {_text(', '.join(map(str, vals[:25])))}", ss["Body"]))

    # --- YARA signatures ---
    yara = analysis.get("yara") or {}
    if yara.get("matches"):
        section("YARA Signature Matches")
        for ym in yara["matches"]:
            el.append(Paragraph(
                f"<b>{ym['rule']}</b> ({ym.get('severity', '')}, +{ym.get('score', 0)})"
                f" — {_text(ym.get('description', ''))}"
                + (f"  [ATT&CK {ym['attack']}]" if ym.get("attack") else ""),
                ss["Body"]))

    # --- MITRE ATT&CK ---
    mitre = analysis.get("mitre") or {}
    if mitre.get("techniques"):
        section("MITRE ATT&CK (Mobile) Mapping")
        rows = [["Technique", "ID", "Tactic"]]
        for t in mitre["techniques"]:
            rows.append([t["name"], t["id"], t.get("tactic", "")])
        mt = Table(rows, colWidths=[78 * mm, 24 * mm, 76 * mm])
        mt.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        el.append(mt)

    # --- Certificate & attack surface ---
    cert = analysis.get("certificate") or {}
    comp = analysis.get("components") or {}
    if cert.get("present") or cert.get("flags") or comp.get("count"):
        section("Signing Certificate & Attack Surface")
        if cert.get("present"):
            el.append(Paragraph(f"<b>Subject:</b> {_text(cert.get('subject', '—'))}", ss["Body"]))
            if cert.get("validity_years") is not None:
                el.append(Paragraph(
                    f"<b>Validity:</b> {cert.get('validity_years')} years"
                    + (" (self-signed)" if cert.get("self_signed") else ""), ss["Body"]))
            if cert.get("sha256"):
                el.append(Paragraph(f"<b>Cert SHA256:</b> {cert['sha256']}", ss["Body"]))
        for fl in cert.get("flags", []):
            el.append(Paragraph(f"<b>{_text(fl['flag'])}</b> — {_text(fl['detail'])}", ss["Body"]))
        if comp.get("count"):
            el.append(Paragraph(
                f"<b>Exported components:</b> {comp['count']} "
                f"({comp.get('unguarded_count', 0)} unguarded service/receiver/provider)", ss["Body"]))

    # --- APKiD ---
    apkid = analysis.get("apkid") or {}
    if apkid.get("findings") or apkid.get("compilers"):
        section("APKiD Fingerprinting")
        for fnd in apkid.get("findings", []):
            el.append(Paragraph(f"<b>{_text(fnd['category'])}:</b> {_text(fnd['name'])}", ss["Body"]))
        if apkid.get("compilers"):
            el.append(Paragraph(f"<b>Compiler:</b> {_text(', '.join(apkid['compilers']))}", ss["Body"]))

    # --- ML classifier ---
    ml = analysis.get("ml") or {}
    if ml.get("available") and "malware_probability" in ml:
        section("Machine-Learning Verdict")
        m = ml.get("model_metrics", {})
        el.append(Paragraph(
            f"Model prediction: <b>{ml.get('prediction', '').upper()}</b> "
            f"(malware probability {ml.get('malware_probability', 0):.0%}, "
            f"confidence {ml.get('confidence', 0):.0%}).", ss["Body"]))
        if m:
            el.append(Paragraph(
                f"<font size=8 color='grey'>Model: precision {m.get('precision_malware', 0):.2f} / "
                f"recall {m.get('recall_malware', 0):.2f} / F1 {m.get('f1_malware', 0):.2f}"
                + (f" / ROC-AUC {m['roc_auc']:.2f}" if m.get('roc_auc') else "")
                + f" on {m.get('n_samples', '?')} samples.</font>", ss["Body"]))
        present = [p["permission"] for p in ml.get("contributing_permissions", [])]
        if present:
            el.append(Paragraph(f"<b>Top contributing permissions:</b> {', '.join(present)}", ss["Body"]))

    # --- VirusTotal ---
    vt = analysis.get("virustotal") or {}
    if vt.get("queried"):
        section("VirusTotal Corroboration")
        fr = vt.get("file", {}) or {}
        if fr.get("found"):
            el.append(Paragraph(
                f"<b>{fr.get('malicious', 0)}</b> malicious / {fr.get('suspicious', 0)} suspicious "
                f"out of {fr.get('total_engines', 0)} engines."
                + (f" Threat label: <b>{_text(fr.get('threat_label'))}</b>." if fr.get("threat_label") else ""),
                ss["Body"]))
            hits = [f"{h['engine']}: {h['result']}" for h in fr.get("engine_hits", [])][:12]
            if hits:
                el.append(Paragraph("<b>Sample detections:</b> " + _text("; ".join(hits)), ss["Body"]))
            if vt.get("flagged_domains"):
                el.append(Paragraph(
                    "<b>Flagged domains:</b> "
                    + _text(", ".join(d["domain"] for d in vt["flagged_domains"])), ss["Body"]))
        else:
            el.append(Paragraph(_text(fr.get("note") or fr.get("error") or
                                "Not found on VirusTotal."), ss["Body"]))

    # --- Bounded agentic investigation ---
    agentic = analysis.get("agentic") or {}
    if agentic:
        section("Agentic Evidence Investigation")
        el.append(Paragraph(
            f"<b>Status:</b> {_text(agentic.get('status', 'unknown'))} &nbsp; "
            f"<b>Provider:</b> {_text(agentic.get('provider', 'â€”'))} / "
            f"{_text(agentic.get('model', 'â€”'))} &nbsp; "
            f"<b>Steps:</b> {_text(agentic.get('steps_used', 0))}", ss["Body"]))
        for hypothesis in agentic.get("hypotheses", [])[:10]:
            evidence = ", ".join(map(str, hypothesis.get("evidence_ids", [])))
            el.append(Paragraph(
                f"â€¢ <b>{_text(hypothesis.get('confidence', 'unknown').title())} confidence:</b> "
                f"{_text(hypothesis.get('claim', ''))}<br/>"
                f"<font size=8 color='grey'>Evidence: {_text(evidence)}</font>", ss["Body"]))
        if agentic.get("gaps"):
            el.append(Paragraph("<b>Evidence gaps:</b>", ss["Body"]))
            bullets(agentic.get("gaps", [])[:10])
        if agentic.get("audit"):
            rows = [["Step", "Action", "Status", "Executed"]]
            for action in agentic["audit"][:20]:
                rows.append([
                    str(action.get("step", "")), action.get("action", ""),
                    action.get("status", ""),
                    "No" if action.get("executed") is False else "Yes",
                ])
            at = Table(rows, colWidths=[14 * mm, 82 * mm, 48 * mm, 28 * mm])
            at.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            el.append(at)

    # --- Recommendations ---
    section("Recommended Actions")
    bullets(report.get("recommended_actions") or analysis.get("recommendations", []))

    el.append(Spacer(1, 10))
    el.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
    el.append(Paragraph(
        f"Report generated by {_text(report.get('generated_by', 'analyzer'))} • "
        "Static analysis only — APK was not executed.", ss["Small"]))

    doc.build(el)
    return buf.getvalue()


def severity_band_text(sev):
    return {
        "Low": "0–20 Low", "Medium": "21–40 Medium",
        "High": "41–70 High", "Critical": "71–100 Critical",
    }.get(sev, sev)
