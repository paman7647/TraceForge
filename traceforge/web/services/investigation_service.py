import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from traceforge.modules.documents import run_document_harvesting
from traceforge.modules.domain import run_domain_dns
from traceforge.modules.email import run_email_breach
from traceforge.modules.identity import run_identity_social
from traceforge.modules.image import run_image_forensics
from traceforge.modules.network import run_network_recon
from traceforge.modules.opsec import run_opsec_audit
from traceforge.platform_detect import which_tool

INVESTIGATION_MODULES: Dict[str, Dict[str, Any]] = {
    "image": {
        "id": "image",
        "name": "Media & Image Forensics",
        "category": "Media & Image Forensics",
        "description": "EXIF metadata extraction, GPS geolocations, IPTC/XMP tags, string carving, and steganography analysis.",
        "input_type": "file",
        "input_label": "Select Image File (.jpg, .png, .tiff, .bmp, .heic, .webp)",
        "supported_tools": ["exiftool", "strings", "zsteg", "binwalk", "jhead", "pngcheck", "mediainfo"],
        "key_capabilities": ["EXIF / IPTC / XMP Extraction", "GPS Coordinate Parsing", "Embedded String Analysis", "LSB Steganography Detection", "Firmware / Trailer Carving"],
    },
    "network": {
        "id": "network",
        "name": "Network & PCAP Forensics",
        "category": "Network, PCAP & Wireless Forensics",
        "description": "PCAP packet dissection, stream reconstruction, protocol statistics, and network conversation triage.",
        "input_type": "file",
        "input_label": "Select Packet Capture (.pcap, .pcapng, .cap)",
        "supported_tools": ["tshark", "tcpdump", "ngrep", "capinfos", "zeek"],
        "key_capabilities": ["Protocol Hierarchy Statistics", "DNS / HTTP / TLS Query Extraction", "Packet Conversation Baselining", "Top Talkers & IP Endpoints"],
    },
    "domain": {
        "id": "domain",
        "name": "Domain, DNS & Infrastructure Intelligence",
        "category": "Domain, DNS & Infrastructure Intelligence",
        "description": "Passive DNS resolution, WHOIS record lookup, subdomains, name servers, and infrastructure profiling.",
        "input_type": "text",
        "input_label": "Enter Target Domain (e.g. example.com)",
        "supported_tools": ["whois", "dig", "subfinder", "dnsrecon", "dnstwist", "wafw00f", "httpx"],
        "key_capabilities": ["WHOIS Registrar & NetRange Queries", "A/AAAA/MX/TXT/NS Record Enumeration", "Subdomain Discovery (Passive)", "WAF & Security Header Detection"],
    },
    "email": {
        "id": "email",
        "name": "Email, Breach & Leak Intelligence",
        "category": "Email, Breach & Leak Intelligence",
        "description": "Email address format validation, MX deliverability check, SPF/DMARC records, and account registration OSINT.",
        "input_type": "text",
        "input_label": "Enter Target Email Address (e.g. operator@domain.com)",
        "supported_tools": ["holehe", "h8mail", "checkdmarc", "emailrep"],
        "key_capabilities": ["Online Service Account Registration Check", "Domain MX & SPF/DMARC Security Posture", "Password Recovery Channel OSINT"],
    },
    "identity": {
        "id": "identity",
        "name": "Identity & Social Reconnaissance (SOCMINT)",
        "category": "Identity, Social & SOCMINT",
        "description": "Cross-platform username availability reconnaissance, profile URL discovery, and public alias indexing.",
        "input_type": "text",
        "input_label": "Enter Target Username / Handle (e.g. jdoe_sec)",
        "supported_tools": ["sherlock", "maigret", "blackbird", "socialscan"],
        "key_capabilities": ["Multi-Site Username Registration Lookup", "Direct Profile URL Verification", "Public Social Presence Mapping"],
    },
    "documents": {
        "id": "documents",
        "name": "Document & Metadata Harvesting",
        "category": "Document & Metadata Harvesting",
        "description": "Metadata extraction from PDF, DOCX, XLSX, OLE macro triage, author tracking, and text harvesting.",
        "input_type": "file",
        "input_label": "Select Document Specimen (.pdf, .docx, .doc, .xlsx, .pptx, .rtf)",
        "supported_tools": ["pdfinfo", "pdftotext", "olevba", "oleid", "docx2txt", "qpdf"],
        "key_capabilities": ["Document Creation / Modification Timestamp Parsing", "Author, Organization & Software Identification", "VBA / OLE Macro Threat Analysis", "Text Content & IOC Harvesting"],
    },
    "opsec": {
        "id": "opsec",
        "name": "OPSEC & Metadata Anonymization",
        "category": "OPSEC & Metadata Anonymization",
        "description": "Forensic metadata sanitization, GPS coordinate stripping, document cleaning, and anonymity auditing.",
        "input_type": "file",
        "input_label": "Select Specimen to Sanitize / Audit",
        "supported_tools": ["mat2", "tor", "proxychains4", "gpg", "age"],
        "key_capabilities": ["Destructive Metadata Sanitization", "Anonymity Route Verification", "Cryptographic Asset Packaging"],
    },
}


def list_investigation_modules() -> List[Dict[str, Any]]:
    """Returns all investigation modules with real-time tool availability."""
    modules: List[Dict[str, Any]] = []
    for mod_id, mod in INVESTIGATION_MODULES.items():
        m_copy = mod.copy()
        m_copy["installed_tools"] = [t for t in mod["supported_tools"] if which_tool(t)]
        m_copy["missing_tools"] = [t for t in mod["supported_tools"] if not which_tool(t)]
        m_copy["is_ready"] = len(m_copy["installed_tools"]) > 0
        modules.append(m_copy)
    return modules


def get_investigation_module(module_id: str) -> Optional[Dict[str, Any]]:
    """Returns specification for a single module."""
    mod = INVESTIGATION_MODULES.get(module_id.lower())
    if not mod:
        return None
    m_copy = mod.copy()
    m_copy["installed_tools"] = [t for t in mod["supported_tools"] if which_tool(t)]
    m_copy["missing_tools"] = [t for t in mod["supported_tools"] if not which_tool(t)]
    m_copy["is_ready"] = len(m_copy["installed_tools"]) > 0
    return m_copy


def run_investigation(module_id: str, target: str, case_id: Optional[str] = None) -> Dict[str, Any]:
    """Dispatches investigation execution to domain modules safely."""
    norm_id = module_id.lower().strip()
    if norm_id not in INVESTIGATION_MODULES:
        raise ValueError(f"Unknown investigation module '{module_id}'")

    if norm_id == "image":
        return run_image_forensics(target, case_id=case_id)
    elif norm_id == "network":
        return run_network_recon(target, case_id=case_id)
    elif norm_id == "domain":
        return run_domain_dns(target, case_id=case_id)
    elif norm_id == "email":
        return run_email_breach(target, case_id=case_id)
    elif norm_id == "identity":
        return run_identity_social(target, case_id=case_id)
    elif norm_id == "documents":
        return run_document_harvesting(target, case_id=case_id)
    elif norm_id == "opsec":
        return run_opsec_audit(target, case_id=case_id)
    else:
        raise ValueError(f"Module '{module_id}' execution is not implemented")
