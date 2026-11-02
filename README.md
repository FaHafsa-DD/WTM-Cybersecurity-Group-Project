# Automated Cybersecurity Assessment & Reporting Assistant

A secure, lightweight, Flask-based web application designed to help students and beginner security analysts ingest, review, verify, and organize penetration testing or vulnerability scan results into professional, audit-ready reports.

---

## Key Features

* **Flexible Data Ingestion:** Automatically parse Nmap XML scan outputs or quickly add custom findings manually.
* **Interactive Review & Verification:** Inspect each finding, edit parameters (ports, services, evidence, risk ratings, and recommendations), and check off human-verification boxes to ensure accuracy.
* **Live Summary Dashboard:** Real-time metrics tracking Total Findings, Affected Hosts, Missing Fields, and Verification Progress, styled with custom color-coded theme cards.
* **Professional Report Generation:** Export verified data into formatted Word documents (`.docx`) featuring structured data tables with custom header shading and a professional footer separator, or clean Markdown files (`.md`).
* **Dynamic Report Status:** Automatically toggles between **DRAFT** and **REVIEWED** status based on team completion of all verification checks.
* **Built-in Security:** Implements robust CSRF session protection and secure XML parsing via `defusedxml` to prevent common web vulnerabilities.

---

## Tech Stack

* **Backend:** Python, Flask
* **Document Processing:** `python-docx` (Word reports)
* **Parsing & Security:** `defusedxml` (Secure XML ingestion)
* **Frontend:** HTML5, Jinja2 Templates, Custom Modern CSS

---

## Project Structure

```text
cybersecurity-project/
│
├── app.py                  # Main Flask application logic & route handlers
├── templates/
│   └── index.html          # Main dashboard UI template
├── static/
│   └── style.css           # Modern stylesheet
└── README.md               # Project documentation

```
---

## Usage Guide

* **Upload Scan Results:** Upload an Nmap XML scan file or use the manual entry form to input specific findings.
* **Review & Edit:** Scroll down to the review section to inspect details, add remediation recommendations, and assess risks.
* **Verify:** Check the "I checked this finding against the source evidence" box for each item to mark it verified.
* **Export Report:** Enter your reviewer name at the bottom and download either a Word (.docx) or Markdown (.md) report.

---

## Disclaimer

This tool is a local prototype intended for authorised security assessments and educational purposes.
An open port or detected signature alone does not definitively prove a vulnerability. Always perform manual verification before sharing or acting upon generated reports.
