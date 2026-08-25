# Reporting & Export Subsystem

TraceForge features a multi-format export pipeline that generates executive briefings, relational spreadsheets, geospatial maps, and standard threat intelligence feeds.

---

## 1. Supported Export Formats

| Format | Output File / Directory | Dependencies | Primary Use Case |
|---|---|---|---|
| **Markdown** | `reports/<CASE_ID>.md` | **Zero (Built-in)** | Technical documentation, GitHub PRs, Obsidian/Logseq notes |
| **HTML (Dark Mode)** | `reports/<CASE_ID>.html` | **Zero (Built-in)** | Standalone browser viewing, executive briefings |
| **Relational CSV** | `exports/csv/*.csv` | **Zero (Built-in)** | Spreadsheet ingestion (Excel, Google Sheets) with formula injection protection |
| **TSV** | `exports/tsv/*.tsv` | **Zero (Built-in)** | Command-line pipelines and AWK scripts |
| **JSON** | `exports/json/case.json` | **Zero (Built-in)** | Programmatic ingestion and API exchange |
| **JSONL Streams** | `exports/jsonl/*.jsonl` | **Zero (Built-in)** | Timesketch, SIEM, and log analytics pipelines |
| **STIX 2.1** | `exports/json/stix21_bundle.json` | **Zero (Built-in)** | Threat Intelligence Platforms (OpenCTI, MISP, Anomali) |
| **MISP Event** | `exports/json/misp_event.json` | **Zero (Built-in)** | Malware Information Sharing Platform (MISP) ingestion |
| **GeoJSON** | `exports/geo/geospatial.geojson` | **Zero (Built-in)** | QGIS, Mapbox, and web mapping interfaces |
| **Google Earth KML**| `exports/geo/geospatial.kml` | **Zero (Built-in)** | Google Earth 3D geospatial overlays |
| **Excel (XLSX)** | `reports/<CASE_ID>.xlsx` | `openpyxl` (Optional) | Multi-tab formatted Excel workbook |
| **Word (DOCX)** | `reports/<CASE_ID>.docx` | `python-docx` (Optional)| Formatted corporate Word document |
| **PDF** | `reports/<CASE_ID>.pdf` | `wkhtmltopdf` / `chromium` (Optional) | Formatted PDF executive report |

---

## 2. Generating Case Exports

Run the export subcommand against the active case:

```bash
# Export all supported formats
traceforge export

# Export with automatic PII redaction
traceforge export --redact

# Export to a custom directory
traceforge export CASE-20260825-A1B2C3 --out /tmp/case_deliverables/
```

---

## 3. CSV Formula Injection Defense

Exporting untrusted evidence strings into CSV files poses a risk of **CSV Formula Injection** (`=`, `+`, `-`, `@`, `\t`, `\r`) when opened in spreadsheet software like Microsoft Excel or LibreOffice Calc.

TraceForge defensively sanitizes every exported field:
- Any cell value beginning with `=,+,-,@` or control characters is automatically prefixed with a single quote (`'`).
- Prevents remote command execution or data exfiltration via DDE links in spreadsheets.

---

## 4. PII & Threat Indicator Redaction

When sharing case reports with external parties or third-party vendors, enable the `--redact` flag:

```bash
traceforge export --redact
```

TraceForge applies context-aware redaction:
- **IPv4 / IPv6 Addresses**: Masked (e.g. `198.51.100.45` ➔ `198.51.***.***`).
- **Email Addresses**: Sanitized (e.g. `analyst@example.com` ➔ `a***t@e***e.com`).
- Original unredacted case evidence in `workspace/` remains unmodified.

---

## 5. Optional Document Renderers

If `openpyxl`, `python-docx`, or `wkhtmltopdf` are not installed, TraceForge gracefully outputs the core formats (HTML, Markdown, CSV, STIX, MISP) and notifies the operator.

To enable optional document renderers:
```bash
pip install openpyxl python-docx
# macOS: brew install wkhtmltopdf
# Linux: sudo apt-get install -y wkhtmltopdf
```
