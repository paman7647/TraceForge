# Responsible Use Policy

**Version:** 1.0.0  
**Effective Date:** 2026  
**Canonical Repository:** [https://github.com/paman7647/TraceForge](https://github.com/paman7647/TraceForge)

---

## 1. Purpose

TraceForge is developed to advance defensive cybersecurity, digital forensics and incident response (DFIR), authorized threat intelligence analysis, and security education. 

This Responsible Use Policy defines the boundaries of intended operation, establishes clear standards for authorized testing, and explicitly prohibits harmful, unlawful, or disruptive activities.

---

## 2. Authorized Use

TraceForge is designed and approved for the following legitimate purposes:

* **Authorized Security Auditing & Penetration Testing:** Assessing systems, networks, and applications where explicit, documented permission has been granted by the system owner.
* **Digital Forensics & Incident Response (DFIR):** Ingesting, preserving, analyzing, and documenting digital evidence following security breaches, insider threats, or forensic triage orders.
* **Defensive Threat Intelligence & Monitoring:** Identifying exposure of organizational assets, correlating indicators of compromise (IOCs), and monitoring defensive postures.
* **Academic Research & Education:** Studying security methodologies, forensic artifacts, network protocols, and data formats in structured educational settings.
* **Capture The Flag (CTF) & Lab Environments:** Operating within local virtualization labs, cyber ranges, or designated competition environments that permit technical analysis.
* **Law Enforcement & Regulatory Inquiries:** Performing forensic and intelligence analysis under lawful warrants, court orders, or statutory mandates.

---

## 3. Prohibited Use

TraceForge must **never** be used for malicious, abusive, or unauthorized activities. Prohibited activities include, but are not limited to:

* **Unauthorized Access:** Probing, scanning, accessing, or exploiting computers, servers, networks, IoT devices, or accounts without verified permission.
* **Disruption & Denial of Service:** Generating high-volume traffic, resource starvation, or malformed packets intended to degrade, crash, or disrupt third-party services.
* **Credential Misuse & Account Takeover:** Testing stolen passwords, spraying credentials, or hijacking sessions against accounts or systems without authorization.
* **Harassment & Stalking:** Doxxing, cyberstalking, harassing, intimidating, or exposing individuals using aggregated open-source or leaked data.
* **Malware Deployment & Persistence:** Utilizing the toolkit to distribute malicious payloads, establish covert backdoors, or facilitate ransomware operations.
* **Bypassing Access Controls:** Circumventing paywalls, authentication portals, CAPTCHAs, or administrative boundaries without authorization.
* **Violating Platform Terms:** Scraping, harvesting, or querying services in direct violation of platform Terms of Service, robots.txt, or developer agreements.

---

## 4. Active Scanning & Network Assessment Standards

When utilizing tools that transmit active network probes (e.g., Nmap, Masscan, TShark, active DNS/HTTP resolvers):

* **Written Scope of Engagement:** Operators must maintain documented scope including authorized IP ranges, domain names, test windows, and permitted techniques.
* **Rate Limiting & Throttling:** Configure scan rates conservatively to avoid overwhelming target infrastructure, firewalls, or intermediate routing equipment.
* **Notification:** Notify target system administrators or network operations centers (NOC) prior to initiating intrusive assessments where required by policy.
* **Immediate Halt:** Immediately suspend testing if unexpected service degradation, operational disruption, or unintended system behavior occurs.

---

## 5. Privacy & Personal Data Handling

OSINT investigations frequently encounter personally identifiable information (PII) such as names, email addresses, phone numbers, usernames, geolocations, and physical addresses:

* **Data Minimization:** Collect only information strictly necessary for the scope of the investigation.
* **Lawful Basis:** Ensure compliance with applicable privacy regulations (e.g., GDPR, CCPA) governing data collection, retention, processing, and disclosure.
* **Redaction for Reporting:** Utilize the built-in `--redact` export engine when sharing deliverables with external parties to mask non-pertinent personal observables.
* **Secure Deletion:** Securely purge case workspaces and temporary evidence when investigation retention periods expire.

---

## 6. Credentials & Breach Intelligence

When analyzing leaked databases, public breach notifications, or password hashes:

* **Defensive Focus:** Use breach data strictly to identify organizational exposure, notify affected individuals, and remediate compromised credentials.
* **No Exploitation:** Do not attempt authentication against live services using discovered or unverified credentials.
* **Protection of Exposure Data:** Store breach dumps and password lists in access-controlled environments with disk-level encryption.

---

## 7. Third-Party Services & API Stewardship

TraceForge interacts with external services, public registries, and third-party APIs (e.g., Shodan, VirusTotal, Holehe, GitHub, DNS servers):

* **API Key Security:** Never hardcode, commit, or publicly share API tokens or private keys in case archives, scripts, or GitHub issues.
* **Quota & Rate Limits:** Respect upstream rate limits, request quotas, and terms of service. Do not deploy parallelized flooding attacks against third-party endpoints.
* **Service Responsibility:** TraceForge maintainers are not responsible for account suspensions, billing charges, or IP blocks resulting from operator usage.

---

## 8. Evidence Handling & Forensic Integrity

For forensic operators handling digital evidence:

* **Preserve Originals:** Never perform destructive or in-place modifications on original evidence files. Always work on bit-stream forensic images or verified working copies.
* **Chain of Custody:** Record acquisition hashes (SHA-256), timestamps, operator identity, and source metadata for every evidence item ingested.
* **Document Tool Versions:** Maintain detailed logs of tool versions, parameters, and environment configurations utilized during analysis.
* **Independent Verification:** Corroborate critical forensic findings using secondary independent tools before finalizing conclusions.

---

## 9. Reporting & Vulnerability Disclosure

When findings reveal unpatched security vulnerabilities, critical exposures, or sensitive leaked information:

* **Coordinated Disclosure:** Notify affected organizations privately and provide reasonable time to mitigate the vulnerability before public disclosure.
* **No Secret Leakage in Reports:** Redact active session tokens, raw private keys, and third-party PII from published summaries or public advisories.

---

## 10. Research, Education & CTFs

* **Isolated Environments:** Perform educational exercises and security research inside isolated virtual machines, local containers, or designated CTF networks.
* **CTF Scope Limits:** Remember that permission to attack a CTF target does **not** grant authorization to probe the hosting cloud infrastructure, platform organizers, or other competitors' infrastructure.

---

## 11. Operator Responsibility

The operator bears full moral, legal, and operational responsibility for the deployment of TraceForge:

* The authors and maintainers do not monitor, approve, or constrain operator activities.
* Installing or using TraceForge confirms your understanding of and compliance with this Responsible Use Policy.
* Violating this policy may lead to legal prosecution, civil liability, employment termination, or revocation of professional security certifications.
