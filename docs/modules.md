# Investigation Modules

TraceForge provides 7 automated investigation modules covering key OSINT and digital forensics workflows.

---

## Overview

| Module | Name | Scope | Mode | Primary Capabilities |
|---|---|---|---|---|
| **01** | **Image & Media Forensics** | Media files (JPG, PNG, TIFF, MP4) | **Passive / Local** | EXIF, GPS coordinates, MakerNotes, hex signatures, strings, steganography, file carving |
| **02** | **Network Recon & PCAP** | PCAP / PCAPNG captures | **Passive / Local** | Protocol hierarchy, conversation breakdown, DNS queries, HTTP URIs, TLS SNI, wireless frames |
| **03** | **Identity & Social Recon** | Usernames / handles | **Passive / API** | Profile discovery across public web platforms (Sherlock, Maigret, Blackbird) |
| **04** | **Email & Breach Analysis** | Email addresses / domains | **Passive / API** | Account registrations (Holehe), public breach triage (h8mail), SPF/DMARC posture, reputation |
| **05** | **Domain & DNS Intel** | Domain names | **Active & Passive** | DNS records (A/AAAA/MX/TXT/SOA), WHOIS registration, passive subdomain enumeration |
| **06** | **Document Harvesting** | PDF, DOCX, XLSX, PPTX | **Passive / Local** | Author metadata, creation timestamps, embedded macros (Oletools), hidden text, secret key leaks |
| **07** | **Defensive OPSEC Audit** | Local host workstation | **Defensive / Local** | Network interfaces, active routing, DNS resolvers, Tor proxy status, storage encryption |

---

## Module 01: Image & Media Forensics

- **Script**: `modules/01_image_forensics.sh` / `traceforge module 1 <path>`
- **Type**: Passive local evidence analysis.
- **Tools Leveraged**: `exiftool`, `binwalk`, `xxd`, `jhead`, `pngcheck`, `steghide`, `tesseract`.
- **What It Analyzes**:
  1. File signature and true MIME type (detecting extension spoofing).
  2. Complete EXIF, IPTC, XMP, and MakerNotes metadata.
  3. Extracted GPS latitude, longitude, and altitude with map links.
  4. ASCII and Unicode string extraction for embedded URLs or threat indicators.
  5. Steganographic payload checks and Binwalk file carving.
- **Example**:
  ```bash
  traceforge module 1 ./evidence_photo.jpg
  ```

---

## Module 02: Network Recon & PCAP Triage

- **Script**: `modules/02_network_recon.sh` / `traceforge module 2 <path>`
- **Type**: Passive offline packet capture analysis.
- **Tools Leveraged**: `tshark`, `capinfos`, `tcpdump`, `aircrack-ng`.
- **What It Analyzes**:
  1. Capture metadata (duration, packet count, interface details).
  2. Protocol hierarchy and top conversation pairs.
  3. Cleartext DNS requests and domain resolutions.
  4. HTTP request headers, User-Agent strings, and requested URIs.
  5. TLS Client Hello Server Name Indication (SNI) hostnames.
  6. 802.11 wireless beacon frames and EAPOL authentication handshakes.
- **Example**:
  ```bash
  traceforge module 2 ./suspicious_traffic.pcap
  ```

---

## Module 03: Identity & Social Recon

- **Script**: `modules/03_identity_social.sh` / `traceforge module 3 <username>`
- **Type**: Passive web reconnaissance across public services.
- **Tools Leveraged**: `sherlock`, `maigret`, `blackbird`, `socialscan`.
- **What It Analyzes**:
  1. Queries 400+ public social networks, developer platforms, and forums.
  2. Validates HTTP response codes and profile status.
  3. Aggregates discovered profile URLs and associated usernames.
- **Example**:
  ```bash
  traceforge module 3 target_handle
  ```

---

## Module 04: Email & Breach Intelligence

- **Script**: `modules/04_email_breach.sh` / `traceforge module 4 <email>`
- **Type**: Passive reconnaissance and breach database lookups.
- **Tools Leveraged**: `holehe`, `h8mail`, `emailrep`, `theharvester`, `checkdmarc`.
- **What It Analyzes**:
  1. Checks account existence across 120+ online platforms via password recovery endpoint probing without triggering login alerts.
  2. Queries public breach databases for known historical exposures.
  3. Analyzes domain SPF, DKIM, and DMARC email authentication records.
- **Example**:
  ```bash
  traceforge module 4 analyst@example.com
  ```

---

## Module 05: Domain & DNS Intelligence

- **Script**: `modules/05_domain_dns.sh` / `traceforge module 5 <domain>`
- **Type**: Passive OSINT and active DNS querying.
- **Tools Leveraged**: `dig`, `whois`, `subfinder`, `amass`, `assetfinder`, `dnstwist`.
- **What It Analyzes**:
  1. Authoritative DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA).
  2. WHOIS registration data (registrar, creation/expiry dates, nameservers).
  3. Passive subdomain enumeration from Certificate Transparency logs.
  4. Permutation analysis for phishing and typosquatting domains.
- **Example**:
  ```bash
  traceforge module 5 example.com
  ```

---

## Module 06: Document & Metadata Harvesting

- **Script**: `modules/06_document_harvesting.sh` / `traceforge module 6 <path>`
- **Type**: Passive local document analysis.
- **Tools Leveraged**: `pdfinfo`, `pdftotext`, `pdfimages`, `oletools` (`olevba`), `mat2`, `tesseract`.
- **What It Analyzes**:
  1. Document author, editing software, creation/modification dates, and revision history.
  2. Extracts embedded text and scans for sensitive patterns (passwords, API tokens, internal paths).
  3. Scans Office documents for VBA macros and suspicious embedded payloads.
  4. Evaluates metadata anonymization with MAT2.
- **Example**:
  ```bash
  traceforge module 6 ./confidential_briefing.pdf
  ```

---

## Module 07: Defensive OPSEC Audit

- **Script**: `modules/07_opsec_anonymization.sh` / `traceforge module 7`
- **Type**: Defensive host posture assessment.
- **Tools Leveraged**: System networking utilities, `tor`, `proxychains`, `openssl`, `macchanger`.
- **What It Analyzes**:
  1. Enumerates active local network interfaces, MAC addresses, and assigned IP addresses.
  2. Validates configured DNS resolvers to detect ISP DNS leakage.
  3. Checks local Tor proxy service status and proxy chaining readiness.
  4. Assesses local disk encryption and cryptographic toolchain status.
- **Example**:
  ```bash
  traceforge module 7
  ```
