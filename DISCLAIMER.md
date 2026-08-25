# Legal Disclaimer & Operational Notice

**Version:** 1.0.0  
**Effective Date:** 2026  
**Canonical Repository:** [https://github.com/paman7647/TraceForge](https://github.com/paman7647/TraceForge)

---

## 1. Core Position & Scope

**TraceForge is an open-source software toolkit and does not authorize, approve, direct, control, or supervise the actions of any operator.**

TraceForge consolidates digital forensics (DFIR), open-source intelligence (OSINT), network analysis, metadata inspection, and evidence management utilities into a standardized workflow. The software is provided as a technological utility for authorized security testing, incident response, digital investigations, defensive auditing, academic research, and lab training.

**The operator is solely responsible for determining whether any action, query, scan, analysis, or data collection performed using TraceForge complies with all applicable laws, regulations, contracts, platform terms of service, privacy requirements, computer misuse statutes, and organizational authorization boundaries.**

---

## 2. Open-Source Information Does Not Mean Unrestricted Use

**The fact that data is publicly accessible on the Internet does not make collecting, storing, processing, correlating, or distributing that data automatically lawful.**

Open-source information, public registries, DNS records, public web pages, and network broadcasts may still be subject to:

* National and regional data protection regulations (e.g., GDPR, CCPA, PIPEDA).
* Intellectual property rights, copyright, and database rights.
* Service-specific Terms of Service (ToS) and Acceptable Use Policies (AUP).
* Anti-harassment, anti-stalking, defamation, and privacy laws.
* Computer access, anti-scraping, and unauthorized access statutes.
* Contractual non-disclosure and employment confidentiality requirements.

TraceForge makes no representation that retrieving or analyzing public or third-party datasets is lawful in any specific jurisdiction. Operators must verify their legal basis prior to conducting OSINT collection.

---

## 3. No Authorization or Permission Is Implied

* **No License to Access Systems:** Downloading, installing, running, modifying, or contributing to TraceForge does **not** grant permission, authorization, or license to access, probe, scan, monitor, or interact with any system, network, host, account, device, service, database, or API without explicit, documented authorization from the rightful owner.
* **Tool Catalog Inclusion:** The inclusion of any tool, binary, script, or service in the TraceForge catalog (e.g., Nmap, Masscan, TShark, Holehe, Sherlock, Shodan) does **not** constitute an endorsement or authorization for its use against any target.
* **Third-Party Targets:** Operating tools against third-party networks, IP addresses, domains, cloud infrastructure, or endpoints requires unambiguous, documented, and properly scoped authorization.

---

## 4. Active Probing vs. Passive Analysis

TraceForge supports both passive forensic analysis and active network exploration. Operators must understand the technical and legal distinctions between these modes:

### Passive Operations
* Extracting metadata from locally provided evidence files (e.g., EXIF tags, PDF structural trees).
* Reading, parsing, and dissecting supplied network capture files (`.pcap`, `.pcapng`).
* Normalizing timestamps, calculating cryptographic hashes, and generating evidence manifests.
* Searching authoritative public DNS or certificate transparency logs without probing target servers.

### Active Operations
* Network port scanning, banner grabbing, and service enumeration.
* Sending synthetic packets, ARP requests, wireless frames, or TLS handshakes to live systems.
* Automated web crawling, directory bruteforcing, or parameter fuzzing.
* Querying cloud endpoints or authenticating against remote API endpoints.

**Active operations transmit network traffic to remote targets, which may trigger security alerts, violate service agreements, consume third-party bandwidth, or constitute unauthorized access under local computer crime legislation.**

---

## 5. Author & Contributor Liability Disclaimer

To the maximum extent permitted by applicable law:

* **No Fitness Warranty:** The authors, maintainers, contributors, administrators, and distributors provide TraceForge **"AS IS"** and **"AS AVAILABLE"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, non-infringement, or compliance with any regulatory regime.
* **No Misuse Liability:** Under no circumstances shall the authors, maintainers, or contributors be held liable for any direct, indirect, incidental, special, exemplary, punitive, or consequential damages (including, but not limited to, loss of data, unauthorized access, operational downtime, legal sanctions, administrative penalties, or third-party claims) arising in any way out of the use, misuse, inability to use, or modification of this software.
* **Statutory Rights Preserved:** Nothing in this disclaimer is intended to exclude or limit liability where such exclusion or limitation is prohibited by applicable statutory law.

---

## 6. No Guarantee of Accuracy or Forensic Admissibility

Digital forensics and OSINT outputs generated by TraceForge are analytical aids:

* **Potential for Errors:** Results may be incomplete, stale, inaccurate, misattributed, affected by third-party API changes, altered by network latency, skewed by missing metadata, or subject to false positives and false negatives.
* **Independent Verification Required:** Operators must independently corroborate, validate, and verify all critical findings, IOCs, geolocation coordinates, and technical observables before drawing investigative conclusions or publishing reports.
* **Evidentiary Admissibility:** TraceForge implements standard cryptographic hashing (SHA-256) and immutable logging, but **does not guarantee that generated reports or exports are legally admissible in court or arbitration**. Admissibility depends on jurisdictional procedural rules, chain-of-custody documentation, evidence collection methodology, and qualified expert testimony.

---

## 7. Third-Party Tools, Dependencies & External Services

* **Independent Governance:** TraceForge integrates and orchestrates third-party software (e.g., ExifTool, TShark, Binwalk, Nmap). Each third-party utility is owned by its respective creators and governed by its own independent license, documentation, terms, and constraints.
* **External SaaS & APIs:** Certain OSINT modules interact with third-party web services, search engines, threat intelligence feeds, or public APIs. TraceForge cannot guarantee the availability, uptime, rate limits, pricing, or terms of third-party services.
* **Attribution Reference:** For full details on third-party licenses and upstream repositories, consult [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## 8. Privacy, Anonymization & Security Limitations

* **No Guaranteed Anonymity:** Tools such as Tor, SOCKS proxies, VPNs, DNS-over-HTTPS, and MAC address randomizers reduce exposure but do **not** guarantee complete anonymity, untraceability, or immunity from lawful interception, traffic correlation, or forensic recovery.
* **Metadata Removal vs. Evidence Spoliation:** Stripping metadata from files for OPSEC must never be performed on original forensic evidence. Altering original files compromises hash integrity and may constitute spoliation of evidence in legal proceedings.

---

## 9. Jurisdictional Variation & No Legal Advice

**The contents of this repository, documentation, source code, and help messages do not constitute legal advice.**

Computer crime laws, wiretapping legislation, privacy statutes, evidence rules, and cyber regulations vary significantly across jurisdictions (e.g., national, state, provincial, municipal, and international laws). 

Operators facing legal, compliance, or regulatory questions must consult qualified legal counsel in the relevant jurisdiction prior to conducting investigations.

---

## 10. Summary Affirmation

By installing, executing, or using TraceForge, you acknowledge that:
1. You have read, understood, and agreed to this Disclaimer and the [Responsible Use Policy](RESPONSIBLE_USE.md).
2. You assume full legal, operational, and ethical responsibility for all actions performed using this software.
3. You possess the requisite authorizations and legal bases for all target systems and datasets processed.
