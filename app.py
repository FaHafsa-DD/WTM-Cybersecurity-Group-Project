
# Cybersecurity Assessment Assistant - Flask Application


import hashlib
import io
import json
import os
import secrets
from datetime import date
from pathlib import Path


from flask import (
    Flask, request, render_template,
    redirect, url_for, send_file, flash, session, abort
)
from defusedxml import ElementTree as ET
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

app = Flask(__name__)
app.secret_key = os.environ.get("REPORT_APP_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

MAX_FINDINGS = 500

DEFAULT_RISK = (
    "Not established by this observation alone; "
    "further assessment required."
)

DEFAULT_RECOMMENDATION = (
    "Confirm the service and version, review its configuration, "
    "and assess whether a security weakness exists.(Draft - reviewer to edit.)"
)

# Prototype data is held in memory and resets when the app restarts.
findings = []
source_name = "No input loaded"
source_hash = "Not available"


def clean(value, default="Not available", limit=10000):
    """Return bounded text without guessing missing information."""
    if value is None:
        return default

    if not isinstance(value, (str, int, float)):
        return default

    value = str(value).strip()
    return value[:limit] if value else default


def make_finding(data):
    """Convert input data into one consistent finding structure."""
    try:
        port = int(data["port"]) if data.get("port") not in (None, "") else None
        if port is not None and not 1 <= port <= 65535:
            port = None
    except (ValueError, TypeError):
        port = None

    return {
        "id": secrets.token_hex(8),
        "title": clean(data.get("title")),
        "host": clean(data.get("host")),
        "port": port,
        "protocol": clean(data.get("protocol")),
        "service": clean(data.get("service")),
        "product": clean(data.get("product")),
        "version": clean(data.get("version")),
        "severity": clean(data.get("severity"), "Not assessed", 50),
        "evidence": clean(data.get("evidence")),
        "evidence_ref": clean(data.get("evidence_ref")),
        "risk": clean(data.get("risk"), DEFAULT_RISK, 3000),
        "recommendation": clean(
            data.get("recommendation"), DEFAULT_RECOMMENDATION, 3000
        ),
        "verified": False,
    }


def parse_nmap_xml(raw, filename):
    """Parse Nmap XML and record open ports only."""
    try:
        root = ET.fromstring(raw)
    except Exception as exc:
        raise ValueError("Invalid or unsafe XML file.") from exc

    if root.tag != "nmaprun":
        raise ValueError(
            "This is not recognised as Nmap XML: expected an nmaprun root."
        )

    results = []

    for host_node in root.findall("host"):
        address = host_node.find("address")
        host = (
            address.get("addr", "Not available")
            if address is not None
            else "Not available"
        )

        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")

            if state is None or state.get("state") != "open":
                continue

            service_node = port_node.find("service")

            try:
                port = int(port_node.get("portid", ""))
                if not 1 <= port <= 65535:
                    port = None
            except (ValueError, TypeError):
                port = None

            protocol = port_node.get("protocol", "Not available")

            service = (
                service_node.get("name", "Not available")
                if service_node is not None else "Not available"
            )
            product = (
                service_node.get("product", "Not available")
                if service_node is not None else "Not available"
            )
            version = (
                service_node.get("version", "Not available")
                if service_node is not None else "Not available"
            )

            evidence = (
                f"Nmap XML reports port {port}/{protocol} as open. "
                f"Service: {service}; product: {product}; version: {version}."
            )

            results.append(make_finding({
                "title": (
                    f"{service.upper()} service detected"
                    if service != "Not available"
                    else "Open port detected"
                ),
                "host": host,
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "evidence": evidence,
                "evidence_ref": (
                    f"{filename} — Nmap XML port element; "
                    "exact source line unavailable"
                ),
            }))

            if len(results) > MAX_FINDINGS:
                raise ValueError("The file contains more than 500 open ports.")

    if not results:
        raise ValueError("No open ports were found in the Nmap XML file.")

    return results


def report_status(items):
    if items and all(item["verified"] for item in items):
        return "REVIEWED"
    return "DRAFT"


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]


@app.before_request
def check_csrf():
    """Protect forms that change application data."""
    if request.method == "POST":
        supplied = request.form.get("csrf", "")
        expected = session.get("_csrf", "")

        if not supplied or not secrets.compare_digest(supplied, expected):
            abort(400, "Invalid form token. Refresh the page and try again.")


@app.context_processor
def inject_template_values():
    return {"csrf": csrf_token}


def snapshot():
    items = [dict(item) for item in findings]
    hosts = len({f["host"] for f in items if f["host"] != "Not available"})
    missing = sum(
        any(f[k] in ("", "Not available", None) for k in ("host", "evidence", "evidence_ref"))
        for f in items
    )
    verified = sum(f["verified"] for f in items)
    return items, hosts, missing, verified


@app.get("/")
def index():
    items, hosts, missing, verified = snapshot()
    return render_template(
        "index.html", findings=items, source_name=source_name,
        source_hash=source_hash, hosts=hosts,
        missing=missing, verified=verified
    )


@app.post("/upload")
def upload():
    global findings, source_name, source_hash

    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file.")
        return redirect(url_for("index"))

    filename = Path(uploaded.filename).name[:200]
    raw = uploaded.read(2 * 1024 * 1024 + 1)

    if len(raw) > 2 * 1024 * 1024:
        flash("The file exceeds the 2 MB limit.")
        return redirect(url_for("index"))

    try:
        extension = Path(filename).suffix.lower()

        if extension == ".xml":
            parsed = parse_nmap_xml(raw, filename)

        elif extension == ".json":
            data = json.loads(raw.decode("utf-8"))

            if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
                raise ValueError('JSON must contain a "findings" list.')

            if not 1 <= len(data["findings"]) <= MAX_FINDINGS:
                raise ValueError("JSON must contain 1–500 findings.")

            if any(not isinstance(item, dict) for item in data["findings"]):
                raise ValueError("Each finding must be a JSON object.")

            parsed = [make_finding(item) for item in data["findings"]]

        else:
            raise ValueError("Upload an .xml or .json file.")

    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        flash(str(exc) or "Could not read the file.")
        return redirect(url_for("index"))

    findings = parsed
    source_name = filename
    source_hash = hashlib.sha256(raw).hexdigest()

    flash(f"Loaded {len(parsed)} finding(s). Review the evidence before verification.")
    return redirect(url_for("index"))


@app.post("/add")
def add():
    global source_name

    data = request.form
    if not data.get("title", "").strip() or not data.get("host", "").strip() or not data.get("evidence", "").strip():
        flash("Title, host/component, and evidence are required.")
        return redirect(url_for("index") + "#add-section")

    item = make_finding({
        **data,
        "evidence_ref": "Manually entered finding"
    })

    if len(findings) >= MAX_FINDINGS:
        flash("Maximum of 500 findings reached.")
        return redirect(url_for("index"))

    findings.append(item)
    source_name = "Manual findings"
    flash("Finding added. Review risk and recommendations before export.")
    return redirect(url_for("index"))


@app.post("/update/<fid>")
def update(fid):
    data = request.form
    item = next((f for f in findings if f["id"] == fid), None)

    if item is None:
        abort(404)

    try:
        port = int(data["port"]) if data.get("port") else None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        flash("Port must be a number between 1 and 65535.")
        return redirect(url_for("index"))

    limits = {
        "title": 200, "host": 255, "protocol": 20, "service": 200,
        "version": 200, "severity": 50, "evidence": 10000,
        "evidence_ref": 500, "risk": 3000, "recommendation": 3000
    }

    for key, limit in limits.items():
        value = data.get(key, "").strip()

        if key in ("title", "host") and not value:
            flash(f"{key.title()} cannot be empty.")
            return redirect(url_for("index"))

        item[key] = clean(value, "Not available", limit)

    item["port"] = port
    item["verified"] = data.get("verified") == "yes"

    flash("Finding saved.")
    return redirect(url_for("index"))


def markdown_report(items, reviewer):
    status = report_status(items)
    lines = [
        f"# Cybersecurity Assessment — {status}",
        "",
        f"- Date: {date.today().isoformat()}",
        f"- Source: {source_name}",
        f"- Reviewer: {reviewer or 'Not provided'}",
        f"- Source SHA-256: `{source_hash}`",
        "",
        (
            "> All findings have been marked verified by the reviewer."
            if status == "REVIEWED"
            else "> DRAFT: verify each finding against its source evidence."
        ),
        "",
        "## Summary",
        "",
        f"Total findings: {len(items)}",
        "",
        "## Findings",
        "",
    ]

    for number, f in enumerate(items, 1):
        component = f"{f['host']}:{f['port'] if f['port'] else 'Not available'}/{f['protocol']}"

        lines.extend([
            f"### {number}. {f['title']}",
            "",
            f"- **Affected component:** {component}",
            f"- **Service:** {f['service']}",
            f"- **Product:** {f['product']}",
            f"- **Version:** {f['version']}",
            f"- **Severity:** {f['severity']}",
            f"- **Evidence reference:** {f['evidence_ref']}",
            f"- **Evidence:** {f['evidence']}",
            f"- **Risk:** {f['risk']}",
            f"- **Recommendation:** {f['recommendation']}",
            f"- **Verification:** {'Verified' if f['verified'] else 'NOT VERIFIED'}",
            "",
        ])

    lines.extend([
        "## Limitations",
        "",
        "An open port alone does not prove a vulnerability. Missing information is not inferred.",
        "",
    ])

    return "\n".join(lines)


def word_report(items, reviewer):
    status = report_status(items)
    doc = Document()

    # Page Margins
    section = doc.sections[0]
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)

    # Base Typography & Colors
    doc.styles["Normal"].font.name = "Arial"
    doc.styles["Normal"].font.size = Pt(10)
    doc.styles["Normal"].font.color.rgb = RGBColor(15, 23, 42)  # Slate dark text
    
    primary_color = RGBColor(15, 23, 42)
    doc.styles["Title"].font.color.rgb = primary_color
    doc.styles["Heading 1"].font.color.rgb = primary_color

    # Document Header / Metadata
    title_heading = doc.add_heading(f"Security Assessment — {status} Report", 0)
    title_heading.paragraph_format.space_after = Pt(12)

    meta_paragraph = doc.add_paragraph()
    meta_paragraph.add_run("Date: ").bold = True
    meta_paragraph.add_run(f"{date.today().isoformat()}\n")
    meta_paragraph.add_run("Source: ").bold = True
    meta_paragraph.add_run(f"{source_name}\n")
    meta_paragraph.add_run("Reviewer: ").bold = True
    meta_paragraph.add_run(f"{reviewer or 'Not provided'}\n")
    meta_paragraph.add_run("Source SHA-256: ").bold = True
    meta_paragraph.add_run(f"{source_hash}")

    if status == "DRAFT":
        draft_notice = doc.add_paragraph("DRAFT: Verify every finding against its source evidence.")
        draft_notice.runs[0].font.color.rgb = RGBColor(180, 83, 9)

    doc.add_heading("Summary", 1)
    doc.add_paragraph(f"Total findings: {len(items)}")

    # Findings Organized in a Table
    doc.add_heading("Findings Overview", 1)

    # Create Table: Columns -> [# | Title & Component | Details / Evidence | Status]
    table = doc.add_table(rows=1, cols=4, style="Table Grid")
    table.autofit = False

    # Set Column Widths (total ~ 6.9 inches width)
    col_widths = [Inches(0.5), Inches(2.2), Inches(3.2), Inches(1.0)]
    
    # Style Header Row
    hdr_cells = table.rows[0].cells
    headers = ["#", "Finding & Component", "Details & Recommendations", "Status"]
    for i, header_text in enumerate(headers):
        hdr_cells[i].text = header_text
        hdr_cells[i].width = col_widths[i]
        for paragraph in hdr_cells[i].paragraphs:
            for run in paragraph.runs:
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)
        
        shading_xml = parse_xml(r'<w:shd {} w:fill="0f172a"/>'.format(nsdecls('w')))
        hdr_cells[i]._tc.get_or_add_tcPr().append(shading_xml)

    # Populate Findings Data into Table Rows
    for number, f in enumerate(items, 1):
        row_cells = table.add_row().cells
        
        component = f"{f['host']}:{f['port'] if f['port'] else 'Not available'}/{f['protocol']}"
        
        # Col 0: Index
        row_cells[0].text = str(number)
        
        # Col 1: Title & Component
        p1 = row_cells[1].paragraphs[0]
        r_title = p1.add_run(f"{f['title']}\n")
        r_title.bold = True
        r_title.font.color.rgb = primary_color
        p1.add_run(f"Host: {component}\nService: {f['service']} ({f['version']})")
        
        # Col 2: Evidence, Risk & Recommendation
        p2 = row_cells[2].paragraphs[0]
        p2.add_run("Evidence: ").bold = True
        p2.add_run(f"{f['evidence']}\n\n")
        p2.add_run("Risk: ").bold = True
        p2.add_run(f"{f['risk']}\n\n")
        p2.add_run("Recommendation: ").bold = True
        p2.add_run(f"{f['recommendation']}")

        # Col 3: Verification Status
        status_text = "Verified" if f["verified"] else "NOT VERIFIED"
        p3 = row_cells[3].paragraphs[0]
        r_status = p3.add_run(status_text)
        r_status.bold = True
        if f["verified"]:
            r_status.font.color.rgb = RGBColor(22, 101, 52)  # Green
        else:
            r_status.font.color.rgb = RGBColor(146, 64, 14)  # Amber

        # Apply cell widths to all rows
        for i, cell in enumerate(row_cells):
            cell.width = col_widths[i]

    # Limitations Section
    doc.add_heading("Limitations", 1)
    doc.add_paragraph(
        "An open port alone does not prove a vulnerability. "
        "Missing information is not inferred."
    )

    # Footer with Horizontal Line
    footer = section.footer
    footer_p = footer.paragraphs[0]
    footer_p.text = "\nCybersecurity Assessment | " + status + " | Human review required"
    footer_p.runs[0].font.color.rgb = RGBColor(100, 116, 139)

    output = io.BytesIO()
    doc.save(output)
    output.seek(0)
    return output

@app.post("/export/<fmt>")
def export_report(fmt):
    if fmt not in ("docx", "md"):
        abort(404)

    items, _, _, _ = snapshot()

    if not items:
        flash("Add or upload findings before exporting.")
        return redirect(url_for("index"))

    reviewer = request.form.get("reviewer", "").strip()[:200]

    if fmt == "md":
        output = io.BytesIO(
            markdown_report(items, reviewer).encode("utf-8")
        )
        return send_file(
            output,
            mimetype="text/markdown; charset=utf-8",
            as_attachment=True,
            download_name="security_assessment.md"
        )

    return send_file(
        word_report(items, reviewer),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name="security_assessment.docx"
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)