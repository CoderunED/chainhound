import json
from datetime import datetime
from pathlib import Path
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

DATA_DIR = Path("data")

GREEN_DARK  = colors.HexColor("#253D2C")
GREEN_MID   = colors.HexColor("#68BA7F")
GREEN_LIGHT = colors.HexColor("#CFFFDC")
MUTED       = colors.HexColor("#7a9c85")
SURFACE     = colors.HexColor("#f4fef7")
WHITE       = colors.white
BLACK       = colors.HexColor("#253D2C")

SEV_COLOR = {
    "CRITICAL": colors.HexColor("#a32d2d"),
    "HIGH":     colors.HexColor("#854f0b"),
    "MEDIUM":   colors.HexColor("#7a5c00"),
    "LOW":      colors.HexColor("#68BA7F"),
    "NONE":     colors.HexColor("#7a9c85"),
}

SEV_BG = {
    "CRITICAL": colors.HexColor("#fff0f0"),
    "HIGH":     colors.HexColor("#fdf3e7"),
    "MEDIUM":   colors.HexColor("#fffbe6"),
    "LOW":      colors.HexColor("#e8f5ec"),
    "NONE":     colors.HexColor("#f4fef7"),
}

def load_json(filename):
    path = DATA_DIR / filename
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)

def build_styles():
    styles = {
        "cover_title": ParagraphStyle("cover_title",
            fontSize=32, textColor=GREEN_DARK, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=6),
        "cover_sub": ParagraphStyle("cover_sub",
            fontSize=14, textColor=MUTED, fontName="Helvetica",
            alignment=TA_CENTER, spaceAfter=4),
        "cover_meta": ParagraphStyle("cover_meta",
            fontSize=11, textColor=MUTED, fontName="Helvetica",
            alignment=TA_CENTER, spaceAfter=2),
        "section_title": ParagraphStyle("section_title",
            fontSize=18, textColor=GREEN_DARK, fontName="Helvetica-Bold",
            spaceBefore=16, spaceAfter=8),
        "subsection": ParagraphStyle("subsection",
            fontSize=13, textColor=GREEN_DARK, fontName="Helvetica-Bold",
            spaceBefore=12, spaceAfter=4),
        "body": ParagraphStyle("body",
            fontSize=10, textColor=BLACK, fontName="Helvetica",
            leading=16, spaceAfter=4),
        "muted": ParagraphStyle("muted",
            fontSize=9, textColor=MUTED, fontName="Helvetica",
            spaceAfter=2),
        "chain": ParagraphStyle("chain",
            fontSize=9, textColor=colors.HexColor("#3b6d11"),
            fontName="Courier", spaceAfter=4),
        "narrative": ParagraphStyle("narrative",
            fontSize=10, textColor=BLACK, fontName="Helvetica",
            leading=17, spaceAfter=6),
        "nar_h1": ParagraphStyle("nar_h1",
            fontSize=15, textColor=GREEN_DARK, fontName="Helvetica-Bold",
            spaceBefore=12, spaceAfter=6),
        "nar_h2": ParagraphStyle("nar_h2",
            fontSize=12, textColor=GREEN_MID, fontName="Helvetica-Bold",
            spaceBefore=10, spaceAfter=4),
        "nar_h3": ParagraphStyle("nar_h3",
            fontSize=11, textColor=GREEN_DARK, fontName="Helvetica-Bold",
            spaceBefore=8, spaceAfter=3),
        "code": ParagraphStyle("code",
            fontSize=9, textColor=colors.HexColor("#3b6d11"),
            fontName="Courier", spaceAfter=3),
    }
    return styles

def render_narrative_text(text, styles):
    flowables = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            flowables.append(Spacer(1, 4))
        elif stripped.startswith("### "):
            flowables.append(Paragraph(stripped[4:], styles["nar_h3"]))
        elif stripped.startswith("## "):
            flowables.append(Paragraph(stripped[3:], styles["nar_h2"]))
        elif stripped.startswith("# "):
            flowables.append(Paragraph(stripped[2:], styles["nar_h1"]))
        elif stripped.startswith("---"):
            flowables.append(HRFlowable(width="100%", thickness=0.5,
                color=GREEN_MID, spaceAfter=6))
        elif stripped.startswith("- "):
            flowables.append(Paragraph("• " + stripped[2:], styles["narrative"]))
        elif stripped.startswith("|"):
            pass
        else:
            line_clean = stripped.replace("**", "<b>", 1)
            while "**" in line_clean:
                line_clean = line_clean.replace("**", "</b>", 1)
            try:
                flowables.append(Paragraph(line_clean, styles["narrative"]))
            except Exception:
                flowables.append(Paragraph(stripped, styles["narrative"]))
    return flowables

def generate_pdf() -> BytesIO:
    summary    = load_json("graph.json")
    paths      = load_json("paths.json")
    findings   = load_json("findings_merged.json")
    narratives = load_json("narratives.json")

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm)

    styles = build_styles()
    story  = []

    # Cover page
    story.append(Spacer(1, 40*mm))
    story.append(Paragraph("ChainHound", styles["cover_title"]))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("IAM Privilege Escalation Report", styles["cover_sub"]))
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="60%", thickness=1, color=GREEN_MID,
        hAlign="CENTER", spaceAfter=8))

    scan_date = datetime.now().strftime("%B %d, %Y %H:%M")
    story.append(Paragraph(f"Generated: {scan_date}", styles["cover_meta"]))

    if summary:
        s = summary.get("summary", {})
        story.append(Paragraph(
            f"Nodes: {s.get('total_nodes','--')}  |  "
            f"Edges: {s.get('total_edges','--')}  |  "
            f"Paths: {s.get('total_paths','--')}",
            styles["cover_meta"]))

    if paths:
        critical = sum(1 for p in paths if p["top_severity"] == "CRITICAL")
        high     = sum(1 for p in paths if p["top_severity"] == "HIGH")
        medium   = sum(1 for p in paths if p["top_severity"] == "MEDIUM")
        story.append(Spacer(1, 6*mm))
        sev_data = [
            ["CRITICAL", "HIGH", "MEDIUM"],
            [str(critical), str(high), str(medium)],
        ]
        sev_table = Table(sev_data, colWidths=[50*mm, 50*mm, 50*mm])
        sev_table.setStyle(TableStyle([
            ("ALIGN",          (0,0), (-1,-1), "CENTER"),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,0),  9),
            ("TEXTCOLOR",      (0,0), (0,0),   SEV_COLOR["CRITICAL"]),
            ("TEXTCOLOR",      (1,0), (1,0),   SEV_COLOR["HIGH"]),
            ("TEXTCOLOR",      (2,0), (2,0),   SEV_COLOR["MEDIUM"]),
            ("FONTNAME",       (0,1), (-1,1),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,1), (-1,1),  22),
            ("TEXTCOLOR",      (0,1), (0,1),   SEV_COLOR["CRITICAL"]),
            ("TEXTCOLOR",      (1,1), (1,1),   SEV_COLOR["HIGH"]),
            ("TEXTCOLOR",      (2,1), (2,1),   SEV_COLOR["MEDIUM"]),
            ("BACKGROUND",     (0,0), (-1,-1), SURFACE),
            ("BOX",            (0,0), (-1,-1), 0.5, GREEN_MID),
            ("INNERGRID",      (0,0), (-1,-1), 0.5, GREEN_MID),
            ("TOPPADDING",     (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 6),
        ]))
        story.append(sev_table)

    story.append(PageBreak())

    # Attack Paths
    story.append(Paragraph("Attack Paths", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREEN_MID, spaceAfter=8))

    if paths:
        table_data = [["#", "Severity", "Score", "Hops", "Attack Chain"]]
        for p in paths:
            table_data.append([
                str(p["path_id"]),
                p["top_severity"],
                f"{p['final_score']}/100",
                str(p["hop_count"]),
                " -> ".join(p["path"]),
            ])
        col_widths = [12*mm, 28*mm, 22*mm, 16*mm, None]
        path_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        ts = TableStyle([
            ("BACKGROUND",     (0,0), (-1,0),  GREEN_DARK),
            ("TEXTCOLOR",      (0,0), (-1,0),  WHITE),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("ALIGN",          (0,0), (-1,-1), "LEFT"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, SURFACE]),
            ("GRID",           (0,0), (-1,-1), 0.4, colors.HexColor("#c8e6d0")),
            ("TOPPADDING",     (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
            ("FONTNAME",       (4,1), (4,-1),  "Courier"),
            ("FONTSIZE",       (4,1), (4,-1),  8),
        ])
        for i, p in enumerate(paths, start=1):
            sev = p["top_severity"]
            ts.add("TEXTCOLOR", (1,i), (1,i), SEV_COLOR.get(sev, MUTED))
            ts.add("FONTNAME",  (1,i), (1,i), "Helvetica-Bold")
            ts.add("TEXTCOLOR", (2,i), (2,i), SEV_COLOR.get(sev, MUTED))
        path_table.setStyle(ts)
        story.append(path_table)
    else:
        story.append(Paragraph("No paths found.", styles["muted"]))

    story.append(PageBreak())

    # Findings
    story.append(Paragraph("Findings", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREEN_MID, spaceAfter=8))

    if findings:
        for record in findings:
            for f in record.get("findings", []):
                sev = f["severity"]
                story.append(Paragraph(f["policy_name"], styles["subsection"]))
                meta_data = [
                    ["Severity", "Score", "Detector"],
                    [sev, f"{f['score']}/100", f.get("detector", "--")],
                ]
                meta_table = Table(meta_data, colWidths=[45*mm, 35*mm, 50*mm])
                meta_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,0),  SURFACE),
                    ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
                    ("FONTSIZE",      (0,0), (-1,-1), 9),
                    ("TEXTCOLOR",     (0,1), (0,1),   SEV_COLOR.get(sev, MUTED)),
                    ("FONTNAME",      (0,1), (0,1),   "Helvetica-Bold"),
                    ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#c8e6d0")),
                    ("TOPPADDING",    (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]))
                story.append(meta_table)
                reasons = f.get("reasons", [])
                if reasons:
                    reason_text = " · ".join(reasons) if isinstance(reasons, list) else str(reasons)
                    story.append(Paragraph(reason_text, styles["muted"]))
                story.append(Spacer(1, 4*mm))
    else:
        story.append(Paragraph("No findings available.", styles["muted"]))

    story.append(PageBreak())

    # Narratives
    story.append(Paragraph("AI Attack Narratives", styles["section_title"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREEN_MID, spaceAfter=8))

    if narratives:
        for n in narratives:
            story.append(Paragraph(
                f"Path {n['path_id']} — {n['attack_chain']}",
                styles["subsection"]))
            story.append(Paragraph(n["attack_chain"], styles["chain"]))
            story.append(Spacer(1, 3*mm))
            story.extend(render_narrative_text(n["narrative"], styles))
            story.append(PageBreak())
    else:
        story.append(Paragraph("No narratives available.", styles["muted"]))

    doc.build(story)
    buf.seek(0)
    return buf
