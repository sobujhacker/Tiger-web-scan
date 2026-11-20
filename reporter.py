import json, os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def save_reports(data):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(REPORT_DIR, "tiger-v6-" + stamp)
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    lines = ["TIGER WEB SCANNER V6", "Target: " + data["target"],
             "Pages reviewed: " + str(data["page_count"]), ""]
    for x in data["findings"]:
        lines += [f'{x["severity"]} | {x["status"]} | {x["name"]}',
                  "URL: " + x["url"], "Evidence: " + x["evidence"],
                  "Fix: " + x["fix"], ""]
    with open(base + ".txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    styles = getSampleStyleSheet()
    story = [Paragraph("TIGER WEB SCANNER V6", styles["Title"]),
             Paragraph("Target: " + data["target"], styles["BodyText"]),
             Paragraph("Pages reviewed: " + str(data["page_count"]), styles["BodyText"]),
             Spacer(1, 12)]
    rows = [["Severity", "Status", "Finding", "Affected URL"]]
    for x in data["findings"]:
        rows.append([x["severity"], x["status"], x["name"], x["url"][:90]])
    table = Table(rows, repeatRows=1, colWidths=[55, 65, 130, 270])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#243247")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), .4, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("WORDWRAP", (0,0), (-1,-1), True)
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Manual review and passive indicators are not proof of exploitability. "
                           "Verify findings in an authorized staging environment.",
                           styles["BodyText"]))
    SimpleDocTemplate(base + ".pdf", pagesize=A4).build(story)
    return [base + ext for ext in (".pdf", ".json", ".txt")]
