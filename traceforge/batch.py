#!/usr/bin/env python3
"""
TraceForge Batch Investigation & Custom Tool Sets Engine
========================================================
Provides unified orchestration, compatibility analysis, sequential/parallel execution,
result normalization, IOC deduplication, entity correlation, profile management,
and merged multi-format reporting for single tools, custom tool sets, and predefined workflows.
"""

import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from traceforge.catalog import Catalog, ToolRecord
from traceforge.config import get_workspace_dir
from traceforge.platform_detect import detect_full_environment, which_tool
from traceforge.runners import ToolExecutionResult, ToolRunner
from traceforge.tools import extract_iocs, defang_ioc

# Regex patterns for input classification
RE_EMAIL = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
RE_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
RE_IPV6 = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
RE_URL = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,8}$", re.IGNORECASE)


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif", ".svg", ".heic", ".raw", ".cr2", ".nef"}
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".dmp"}
DOC_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".rtf", ".epub"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz", ".iso"}

ACTIVE_NETWORK_BINARIES = {
    "nmap", "masscan", "nikto", "hydra", "aircrack-ng", "wafw00f", "gobuster",
    "dirsearch", "sublist3r", "theharvester", "amass", "subfinder", "httpx",
    "katana", "nuclei", "arjun", "paramspider", "gau", "waybackurls", "cve-bin-tool",
    "shodan", "censys", "censys-cli", "whatweb", "dnsrecon", "dnstwist", "fierce",
    "knockpy", "testssl.sh", "sslscan", "sslyze", "wpscan", "droopescan"
}

PREDEFINED_WORKFLOWS: Dict[str, Dict[str, Any]] = {
    "image": {
        "id": "image",
        "name": "Media & Image Forensics",
        "description": "Metadata extraction, steganography inspection, embedded payload analysis, and image sanitization.",
        "input_types": ["image", "file", "directory"],
        "tools": [
            "exiftool", "binwalk", "strings", "mat2", "pngcheck", "jhead",
            "steghide", "zsteg", "ffmpeg", "ffprobe", "mediainfo",
            "tesseract", "foremost", "yara",
        ],
    },
    "network": {
        "id": "network",
        "name": "Network, PCAP & Packet Analysis",
        "description": "Offline packet dissection, protocol analysis, flow statistics, and beacon detection.",
        "input_types": ["pcap", "file"],
        "tools": ["tshark", "tcpdump", "capinfos", "zeek", "snort", "ngrep", "nmap"],
    },
    "domain": {
        "id": "domain",
        "name": "Domain, DNS & Infrastructure Recon",
        "description": "Passive DNS resolution, WHOIS querying, subdomain enumeration, and WAF fingerprinting.",
        "input_types": ["domain", "url", "ipv4"],
        "tools": [
            "subfinder", "whois", "dig", "dnsrecon", "dnstwist",
            "wafw00f", "assetfinder", "httpx", "dnsx", "naabu",
        ],
    },
    "email": {
        "id": "email",
        "name": "Email, Breach & Identity Exposure",
        "description": "Account registration reconnaissance, email validity testing, and credential leak discovery.",
        "input_types": ["email", "username", "text"],
        "tools": ["holehe", "h8mail", "emailrep", "theHarvester", "checkdmarc"],
    },
    "identity": {
        "id": "identity",
        "name": "Identity & Social Footprint (SOCMINT)",
        "description": "Cross-platform username enumeration and social media profile mapping.",
        "input_types": ["username", "email", "text"],
        "tools": ["sherlock", "maigret", "blackbird", "socialscan", "ghunt"],
    },
    "documents": {
        "id": "documents",
        "name": "Document & Metadata Harvesting",
        "description": "PDF/Office metadata harvesting, macro detection, and text extraction.",
        "input_types": ["document", "file", "directory"],
        "tools": [
            "exiftool", "pdftotext", "pdfinfo", "pdfimages", "mat2",
            "qpdf", "olevba", "oleid", "mutool", "docx2txt",
        ],
    },
    "opsec": {
        "id": "opsec",
        "name": "OPSEC & Artifact Anonymization",
        "description": "Local artifact cleaning, privacy stripping, and encryption verification.",
        "input_types": ["file", "directory", "image", "document"],
        "tools": ["mat2", "exiftool", "age", "gpg"],
    },
}



def classify_input_type(input_str: str) -> Dict[str, Any]:
    """Classifies an input string into its primary and specific forensic types."""
    val = input_str.strip()
    if not val:
        return {"type": "empty", "specific": "empty", "value": "", "exists": False, "length": 0}

    # Only treat as filesystem path if it actually exists or looks like a file with a known extension
    p = Path(val)
    if p.exists() and val not in (".", "..", "/"):
        if p.is_dir():
            return {"type": "directory", "specific": "directory", "path": str(p.resolve()), "exists": True, "size": 0}
        if p.is_file():
            ext = p.suffix.lower()
            specific = "file"
            if ext in IMAGE_EXTENSIONS:
                specific = "image"
            elif ext in PCAP_EXTENSIONS:
                specific = "pcap"
            elif ext in DOC_EXTENSIONS:
                specific = "document"
            elif ext in ARCHIVE_EXTENSIONS:
                specific = "archive"
            elif ext == ".json":
                specific = "json"
            elif ext == ".jsonl":
                specific = "jsonl"
            elif ext in (".csv", ".tsv"):
                specific = "csv"
            elif ext in (".txt", ".log", ".md", ".py", ".sh"):
                specific = "text_file"
            return {
                "type": "file",
                "specific": specific,
                "path": str(p.resolve()),
                "filename": p.name,
                "extension": ext,
                "exists": True,
                "size": p.stat().st_size,
            }

    ext = p.suffix.lower()
    if ext:
        specific = "file"
        if ext in IMAGE_EXTENSIONS:
            specific = "image"
        elif ext in PCAP_EXTENSIONS:
            specific = "pcap"
        elif ext in DOC_EXTENSIONS:
            specific = "document"
        elif ext in ARCHIVE_EXTENSIONS:
            specific = "archive"
        elif ext == ".json":
            specific = "json"
        elif ext == ".jsonl":
            specific = "jsonl"
        elif ext in (".csv", ".tsv"):
            specific = "csv"
        elif ext in (".txt", ".log", ".md", ".py", ".sh"):
            specific = "text_file"

        if specific != "file":
            return {
                "type": "file",
                "specific": specific,
                "path": val,
                "filename": p.name,
                "extension": ext,
                "exists": False,
                "size": 0,
            }

    # Non-filesystem string inputs
    if RE_URL.match(val):
        return {"type": "url", "specific": "url", "value": val, "exists": False}
    if RE_EMAIL.match(val):
        return {"type": "email", "specific": "email", "value": val, "exists": False}
    if RE_IPV4.match(val):
        return {"type": "ipv4", "specific": "ip", "value": val, "exists": False}
    if RE_IPV6.match(val):
        return {"type": "ipv6", "specific": "ip", "value": val, "exists": False}
    if RE_DOMAIN.match(val):
        return {"type": "domain", "specific": "domain", "value": val, "exists": False}
    if RE_SHA256.match(val):
        return {"type": "hash", "specific": "sha256", "value": val, "exists": False}
    if RE_SHA1.match(val):
        return {"type": "hash", "specific": "sha1", "value": val, "exists": False}
    if RE_MD5.match(val):
        return {"type": "hash", "specific": "md5", "value": val, "exists": False}
    if RE_CVE.match(val):
        return {"type": "cve", "specific": "cve", "value": val, "exists": False}
    if val.startswith("EVID-"):
        return {"type": "case_evidence", "specific": "case_evidence", "evidence_id": val, "exists": False}
    if len(val.split()) == 1 and len(val) <= 32 and val.replace("_", "").replace("-", "").isalnum():
        return {"type": "username", "specific": "username", "value": val, "exists": False}

    return {"type": "text", "specific": "text", "value": val, "exists": False, "length": len(val)}



def is_active_network_tool(tool_rec_or_binary: Union[ToolRecord, str]) -> bool:
    """Checks whether a tool performs active network requests."""
    binary = tool_rec_or_binary.binary if isinstance(tool_rec_or_binary, ToolRecord) else str(tool_rec_or_binary).lower()
    return binary.lower() in ACTIVE_NETWORK_BINARIES


def evaluate_tool_input_compatibility(tool: ToolRecord, input_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates whether a catalog tool is compatible with a given input.
    Returns compatibility status, boolean flag, detailed rationale, and default recommended arguments.
    """
    binary = tool.binary.lower()
    cat = tool.category.lower()
    itype = input_info["type"]
    ispec = input_info.get("specific", itype)
    path = input_info.get("path") or input_info.get("value", "")

    # Universal text tools
    if binary in ("strings", "jq", "grep", "ripgrep", "rg", "sed", "awk"):
        if itype in ("file", "directory", "text"):
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": "Universal stream/file extraction utility",
                "suggested_args": [path] if itype == "file" else [],
            }

    # PCAP & Packet Forensics tools
    if cat.startswith("network") or binary in ("tshark", "tcpdump", "ngrep", "zeek", "snort", "capinfos"):
        if ispec == "pcap":
            args = ["-r", path] if binary in ("tshark", "tcpdump", "zeek") else [path]
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": "PCAP capture input matches packet dissector",
                "suggested_args": args,
            }
        elif itype == "file":
            return {
                "compatibility": "INCOMPATIBLE",
                "is_compatible": False,
                "reason": f"Tool '{tool.name}' requires a PCAP capture (.pcap, .pcapng); detected {ispec}",
                "suggested_args": [],
            }
        elif itype in ("domain", "ipv4", "ipv6", "url") and binary in ("nmap", "masscan", "nikto", "hydra"):
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": f"Network probe target ({itype}) compatible with scanner",
                "suggested_args": [path],
            }
        else:
            return {
                "compatibility": "INCOMPATIBLE",
                "is_compatible": False,
                "reason": f"Network tool '{tool.name}' cannot process {itype} input directly",
                "suggested_args": [],
            }

    # Media & Image Forensics tools
    if cat.startswith("media") or binary in ("exiftool", "binwalk", "mat2", "pngcheck", "jhead", "steghide", "ffmpeg", "foremost", "scalpel", "testdisk"):
        if ispec in ("image", "file", "document", "archive", "directory"):
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": f"File artifact ({ispec}) matches forensic analyzer",
                "suggested_args": [path],
            }
        else:
            return {
                "compatibility": "INCOMPATIBLE",
                "is_compatible": False,
                "reason": f"Media forensics tool '{tool.name}' requires a file specimen; got {itype}",
                "suggested_args": [],
            }

    # Domain / DNS / Web tools
    if cat.startswith("domain") or binary in ("subfinder", "whois", "dig", "dnsrecon", "dnstwist", "wafw00f", "assetfinder", "shodan", "censys", "whatweb"):
        if itype in ("domain", "ipv4", "ipv6", "url"):
            target_arg = path
            if itype == "url" and binary in ("subfinder", "whois", "dig", "dnsrecon"):
                import urllib.parse
                try:
                    target_arg = urllib.parse.urlparse(path).hostname or path
                except Exception:
                    pass
            args = ["-d", target_arg] if binary in ("subfinder", "dnsrecon", "dnstwist", "assetfinder") else [target_arg]
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": f"Target entity ({itype}: {target_arg}) matches DNS/domain engine",
                "suggested_args": args,
            }
        elif itype == "file":
            return {
                "compatibility": "INCOMPATIBLE",
                "is_compatible": False,
                "reason": f"Domain tool '{tool.name}' requires a domain or hostname string, not a local file",
                "suggested_args": [],
            }

    # Identity / Social / Email tools
    if cat.startswith("identity") or cat.startswith("email") or binary in ("sherlock", "holehe", "h8mail", "emailrep", "maigret", "blackbird", "socialscan", "theharvester", "checkdmarc"):
        if itype in ("email", "username", "text", "domain"):
            if binary in ("holehe", "h8mail", "emailrep") and itype != "email":
                return {
                    "compatibility": "INCOMPATIBLE",
                    "is_compatible": False,
                    "reason": f"Tool '{tool.name}' requires an email address; got {itype}",
                    "suggested_args": [],
                }
            if binary in ("sherlock", "maigret", "blackbird") and itype not in ("username", "email", "text"):
                return {
                    "compatibility": "INCOMPATIBLE",
                    "is_compatible": False,
                    "reason": f"SOCMINT tool '{tool.name}' requires a username or handle; got {itype}",
                    "suggested_args": [],
                }
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": f"Identity indicator ({itype}: {path}) compatible with OSINT tool",
                "suggested_args": [path],
            }
        elif itype == "file":
            return {
                "compatibility": "INCOMPATIBLE",
                "is_compatible": False,
                "reason": f"Identity tool '{tool.name}' requires an observable string (username/email), not a local file",
                "suggested_args": [],
            }

    # Document & Metadata tools
    if cat.startswith("document") or binary in ("pdftotext", "pdfinfo", "qpdf", "olevba", "pdfid", "pdf-parser"):
        if ispec in ("document", "file", "directory"):
            return {
                "compatibility": "COMPATIBLE",
                "is_compatible": True,
                "reason": f"Document specimen ({ispec}) matches document parser",
                "suggested_args": [path],
            }
        else:
            return {
                "compatibility": "INCOMPATIBLE",
                "is_compatible": False,
                "reason": f"Document tool '{tool.name}' requires a document file; got {itype}",
                "suggested_args": [],
            }

    # Default fallback
    if itype in ("file", "directory"):
        return {
            "compatibility": "COMPATIBLE",
            "is_compatible": True,
            "reason": f"Standard file/directory input passed to '{tool.binary}'",
            "suggested_args": [path],
        }

    return {
        "compatibility": "UNKNOWN",
        "is_compatible": True,
        "reason": f"General input '{path}' passed directly to '{tool.binary}'",
        "suggested_args": [path],
    }


class BatchPlan:
    """Represents a pre-flight validated execution plan for a batch of tools."""

    def __init__(
        self,
        raw_input: str,
        input_info: Dict[str, Any],
        tools: List[ToolRecord],
        platform_env: Optional[Dict[str, Any]] = None,
        execution_mode: str = "sequential",
        max_workers: int = 3,
        per_tool_timeout: int = 60,
    ):
        self.raw_input = raw_input
        self.input_info = input_info
        self.tools = tools
        self.platform_env = platform_env or detect_full_environment()
        self.execution_mode = execution_mode
        self.max_workers = max_workers
        self.per_tool_timeout = per_tool_timeout

        self.executable_tools: List[Dict[str, Any]] = []
        self.missing_tools: List[Dict[str, Any]] = []
        self.unavailable_tools: List[Dict[str, Any]] = []
        self.incompatible_tools: List[Dict[str, Any]] = []
        self.active_network_tools: List[Dict[str, Any]] = []

        self._evaluate()

    def _evaluate(self) -> None:
        for tool in self.tools:
            cap = tool.get_platform_capability(self.platform_env)
            comp = evaluate_tool_input_compatibility(tool, self.input_info)
            is_active = is_active_network_tool(tool)

            entry = {
                "id": tool.id,
                "name": tool.name,
                "binary": tool.binary,
                "category": tool.category,
                "ecosystem": tool.ecosystem,
                "is_installed": tool.is_installed,
                "is_available": cap["is_available"],
                "availability": cap["availability"],
                "platform_reason": cap["reason"],
                "is_compatible": comp["is_compatible"],
                "compatibility": comp["compatibility"],
                "compatibility_reason": comp["reason"],
                "suggested_args": comp["suggested_args"],
                "is_active_network": is_active,
            }

            if is_active:
                self.active_network_tools.append(entry)

            if not cap["is_available"]:
                self.unavailable_tools.append(entry)
            elif not comp["is_compatible"]:
                self.incompatible_tools.append(entry)
            elif not tool.is_installed:
                self.missing_tools.append(entry)
            else:
                self.executable_tools.append(entry)

    @property
    def has_active_network_tools(self) -> bool:
        return len(self.active_network_tools) > 0

    @property
    def is_executable(self) -> bool:
        return len(self.executable_tools) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input": self.raw_input,
            "input_type": self.input_info["type"].upper(),
            "input_specific": self.input_info.get("specific", self.input_info["type"]),
            "platform": self.platform_env.get("display_name", self.platform_env.get("os_name")),
            "execution_mode": self.execution_mode,
            "max_workers": self.max_workers,
            "per_tool_timeout": self.per_tool_timeout,
            "total_selected": len(self.tools),
            "executable_count": len(self.executable_tools),
            "missing_count": len(self.missing_tools),
            "unavailable_count": len(self.unavailable_tools),
            "incompatible_count": len(self.incompatible_tools),
            "active_network_count": len(self.active_network_tools),
            "has_active_network_tools": self.has_active_network_tools,
            "executable_tools": self.executable_tools,
            "missing_tools": self.missing_tools,
            "unavailable_tools": self.unavailable_tools,
            "incompatible_tools": self.incompatible_tools,
        }


class NormalizedToolResult:
    """Holds a single normalized tool execution result."""

    def __init__(
        self,
        tool_id: int,
        tool_name: str,
        binary: str,
        command: List[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_seconds: float,
        executed_at: str,
        input_target: str,
    ):
        self.tool_id = tool_id
        self.tool_name = tool_name
        self.binary = binary
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration_seconds
        self.executed_at = executed_at
        self.input_target = input_target

        self.findings: List[Dict[str, Any]] = []
        self.indicators: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.warnings: List[str] = []

        self._normalize()

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def _normalize(self) -> None:
        """Parses output into structured findings, indicators, and metadata."""
        combined_text = f"{self.stdout}\n{self.stderr}"

        # Extract IOCs
        raw_iocs = extract_iocs(combined_text, source=f"tool:{self.binary}")
        self.indicators = raw_iocs

        # Extract basic findings from stdout
        lines = [line.strip() for line in self.stdout.splitlines() if line.strip()]
        for line in lines[:30]:
            if any(term in line.lower() for term in ("found", "vulnerable", "warning", "alert", "cve-", "exif", "gps", "hidden")):
                self.findings.append({
                    "title": line[:100],
                    "details": line,
                    "severity": "Medium" if "cve-" in line.lower() or "vulnerable" in line.lower() else "Low",
                    "source_tool": self.binary,
                })

        if self.stderr and self.exit_code != 0:
            self.warnings.append(self.stderr.strip()[:200])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "binary": self.binary,
            "command": " ".join(self.command),
            "exit_code": self.exit_code,
            "success": self.success,
            "duration_seconds": round(self.duration_seconds, 3),
            "executed_at": self.executed_at,
            "input_target": self.input_target,
            "findings_count": len(self.findings),
            "indicators_count": len(self.indicators),
            "findings": self.findings,
            "indicators": self.indicators,
            "metadata": self.metadata,
            "warnings": self.warnings,
            "raw_stdout_len": len(self.stdout),
            "raw_stderr_len": len(self.stderr),
            "raw_stdout": self.stdout[:40000],
            "raw_stderr": self.stderr[:10000],
        }


class BatchResult:
    """Aggregates, deduplicates, and correlates all normalized results from a batch run."""

    def __init__(
        self,
        job_id: str,
        input_target: str,
        input_type: str,
        workflow_name: str,
        started_at: str,
        completed_at: str,
        duration_seconds: float,
        tool_results: List[NormalizedToolResult],
        skipped_tools: List[Dict[str, Any]],
    ):
        self.job_id = job_id
        self.input_target = input_target
        self.input_type = input_type
        self.workflow_name = workflow_name
        self.started_at = started_at
        self.completed_at = completed_at
        self.duration_seconds = duration_seconds
        self.tool_results = tool_results
        self.skipped_tools = skipped_tools

        self.deduplicated_indicators: List[Dict[str, Any]] = []
        self.aggregated_findings: List[Dict[str, Any]] = []
        self._deduplicate_and_aggregate()

    @property
    def total_tools_run(self) -> int:
        return len(self.tool_results)

    @property
    def successful_count(self) -> int:
        return sum(1 for r in self.tool_results if r.success)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.tool_results if not r.success)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped_tools)

    def _deduplicate_and_aggregate(self) -> None:
        """Deduplicates indicators across all tool outputs while retaining attribution."""
        ioc_map: Dict[str, Dict[str, Any]] = {}

        for r in self.tool_results:
            # Aggregate findings
            self.aggregated_findings.extend(r.findings)

            # Deduplicate IOCs
            for ioc in r.indicators:
                key = f"{ioc['type']}:{ioc['value']}"
                if key in ioc_map:
                    if r.binary not in ioc_map[key]["sources"]:
                        ioc_map[key]["sources"].append(r.binary)
                    ioc_map[key]["last_seen"] = r.executed_at
                else:
                    ioc_copy = dict(ioc)
                    ioc_copy["sources"] = [r.binary]
                    ioc_map[key] = ioc_copy

        self.deduplicated_indicators = list(ioc_map.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "input_target": self.input_target,
            "input_type": self.input_type,
            "workflow_name": self.workflow_name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_tools_run": self.total_tools_run,
            "successful_count": self.successful_count,
            "failed_count": self.failed_count,
            "skipped_count": self.skipped_count,
            "deduplicated_indicators_count": len(self.deduplicated_indicators),
            "aggregated_findings_count": len(self.aggregated_findings),
            "tool_results": [r.to_dict() for r in self.tool_results],
            "skipped_tools": self.skipped_tools,
            "indicators": self.deduplicated_indicators,
            "findings": self.aggregated_findings,
        }

    def generate_markdown_report(self) -> str:
        """Generates a comprehensive merged Markdown investigation report."""
        lines = [
            f"# TraceForge Batch Investigation Report",
            f"",
            f"**Job ID**: `{self.job_id}`  ",
            f"**Target Input**: `{self.input_target}` ({self.input_type})  ",
            f"**Workflow**: `{self.workflow_name}`  ",
            f"**Timestamp**: `{self.started_at}` (Duration: {round(self.duration_seconds, 2)}s)  ",
            f"",
            f"---",
            f"",
            f"## 1. Execution Summary",
            f"",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Total Tools Executed | **{self.total_tools_run}** |",
            f"| Successful | **{self.successful_count}** |",
            f"| Failed / Errors | **{self.failed_count}** |",
            f"| Skipped (Incompatible / Missing) | **{self.skipped_count}** |",
            f"| Deduplicated IOCs Extracted | **{len(self.deduplicated_indicators)}** |",
            f"| Findings Identified | **{len(self.aggregated_findings)}** |",
            f"",
            f"---",
            f"",
            f"## 2. Deduplicated Indicators of Compromise (IOCs)",
            f"",
        ]

        if self.deduplicated_indicators:
            lines.append("| Type | Defanged Value | Attributed Sources |")
            lines.append("|---|---|---|")
            for ioc in self.deduplicated_indicators:
                srcs = ", ".join(ioc.get("sources", []))
                lines.append(f"| `{ioc['type'].upper()}` | `{ioc['defanged']}` | {srcs} |")
        else:
            lines.append("*No indicators extracted.*")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 3. Individual Tool Execution Results",
            f"",
        ])

        for r in self.tool_results:
            status_tag = "✓ SUCCESS" if r.success else f"✗ FAILED (Exit Code {r.exit_code})"
            lines.extend([
                f"### {r.tool_name} (`{r.binary}`) — {status_tag}",
                f"- **Command**: `{ ' '.join(r.command) }`",
                f"- **Duration**: {round(r.duration_seconds, 3)}s",
                f"- **Findings**: {len(r.findings)} | **Indicators**: {len(r.indicators)}",
                f"",
            ])
            if r.stdout:
                lines.extend([
                    f"```text",
                    r.stdout.strip()[:2000] + ("\n... [truncated]" if len(r.stdout) > 2000 else ""),
                    f"```",
                    f"",
                ])
            if r.stderr and not r.success:
                lines.extend([
                    f"**Stderr Error Output**:",
                    f"```text",
                    r.stderr.strip()[:1000],
                    f"```",
                    f"",
                ])

        if self.skipped_tools:
            lines.extend([
                f"---",
                f"",
                f"## 4. Skipped Tools",
                f"",
                f"| Tool Name | Binary | Reason |",
                f"|---|---|---|",
            ])
            for sk in self.skipped_tools:
                reason = sk.get("compatibility_reason") or sk.get("platform_reason") or "Skipped"
                lines.append(f"| {sk.get('name', 'Unknown')} | `{sk.get('binary', '-')}` | {reason} |")

        return "\n".join(lines)


class BatchEngine:
    """Orchestrates custom tool sets, pre-flight plans, and batch executions."""

    def __init__(self, catalog: Optional[Catalog] = None):
        self.catalog = catalog or Catalog()
        self.platform_env = detect_full_environment()
        self._profiles_file = get_workspace_dir() / "custom_profiles.json"
        self._history_file = get_workspace_dir() / "batch_history.json"
        self._active_cancellations: Dict[str, threading.Event] = {}

    def create_plan(
        self,
        raw_input: str,
        tool_identifiers: List[Union[str, int]],
        execution_mode: str = "sequential",
        max_workers: int = 3,
        per_tool_timeout: int = 60,
        timeout_seconds: Optional[int] = None,
    ) -> BatchPlan:
        """Constructs and validates a batch execution plan for an input and a list of tool queries."""
        input_info = classify_input_type(raw_input)
        resolved_tools: List[ToolRecord] = []
        timeout = timeout_seconds if timeout_seconds is not None else per_tool_timeout

        for tid in tool_identifiers:
            t = self.catalog.find_tool(str(tid))
            if t and t not in resolved_tools:
                resolved_tools.append(t)

        return BatchPlan(
            raw_input=raw_input,
            input_info=input_info,
            tools=resolved_tools,
            platform_env=self.platform_env,
            execution_mode=execution_mode,
            max_workers=max_workers,
            per_tool_timeout=timeout,
        )

    def create_plan_for_workflow(
        self,
        raw_input: str,
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        execution_mode: str = "sequential",
        max_workers: int = 3,
        per_tool_timeout: int = 60,
        timeout_seconds: Optional[int] = None,
    ) -> BatchPlan:
        """Constructs a batch plan for a predefined investigation category."""
        target_id = workflow_id or workflow_name or ""
        spec = PREDEFINED_WORKFLOWS.get(target_id.lower())
        if not spec:
            raise ValueError(f"Unknown workflow ID: '{target_id}'")

        timeout = timeout_seconds if timeout_seconds is not None else per_tool_timeout

        return self.create_plan(
            raw_input=raw_input,
            tool_identifiers=spec["tools"],
            execution_mode=execution_mode,
            max_workers=max_workers,
            per_tool_timeout=timeout,
        )

    def execute_plan(
        self,
        plan: BatchPlan,
        job_id: Optional[str] = None,
        on_tool_start: Optional[Callable[[str, int, int], None]] = None,
        on_tool_complete: Optional[Callable[[NormalizedToolResult, int, int], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> BatchResult:
        """
        Executes a validated BatchPlan sequentially or in parallel.
        Normalizes outputs, deduplicates indicators, and records execution history.
        """
        if job_id is None:
            job_id = f"batch-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

        if cancel_event:
            self._active_cancellations[job_id] = cancel_event

        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        t_start = time.time()

        if on_log:
            on_log(f"[*] Starting Batch Investigation '{job_id}' against '{plan.raw_input}' ({plan.input_info['type']})...")

        results: List[NormalizedToolResult] = []
        skipped = list(plan.unavailable_tools) + list(plan.incompatible_tools) + list(plan.missing_tools)
        total_executable = len(plan.executable_tools)

        def _execute_single(idx: int, tinfo: Dict[str, Any]) -> Optional[NormalizedToolResult]:
            if cancel_event and cancel_event.is_set():
                if on_log:
                    on_log(f"[!] Batch cancelled. Skipping tool {tinfo['binary']}.")
                return None

            if on_tool_start:
                on_tool_start(tinfo["binary"], idx + 1, total_executable)
            if on_log:
                on_log(f"[*] [{idx + 1}/{total_executable}] Spawning '{tinfo['name']}' ({tinfo['binary']})...")

            args = list(tinfo["suggested_args"])
            res = ToolRunner.run_catalog_tool(
                tool_query=tinfo["binary"],
                args=args,
                timeout=plan.per_tool_timeout,
            )

            norm = NormalizedToolResult(
                tool_id=tinfo["id"],
                tool_name=tinfo["name"],
                binary=tinfo["binary"],
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                duration_seconds=res.duration_seconds,
                executed_at=res.executed_at,
                input_target=plan.raw_input,
            )

            if on_tool_complete:
                on_tool_complete(norm, idx + 1, total_executable)
            if on_log:
                tag = "SUCCESS" if norm.success else f"FAILED (Exit {norm.exit_code})"
                on_log(f"[+] [{idx + 1}/{total_executable}] Completed '{tinfo['binary']}' in {round(norm.duration_seconds, 2)}s [{tag}].")

            return norm

        # Execution pathway
        if plan.execution_mode == "parallel" and total_executable > 1:
            workers = min(plan.max_workers, total_executable, 6)
            if on_log:
                on_log(f"[*] Dispatching {total_executable} tools across {workers} parallel worker threads...")

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(_execute_single, i, t) for i, t in enumerate(plan.executable_tools)]
                for fut in futures:
                    try:
                        res = fut.result()
                        if res:
                            results.append(res)
                    except Exception as e:
                        if on_log:
                            on_log(f"[!] Thread worker error: {e}")
        else:
            # Sequential execution
            for i, t in enumerate(plan.executable_tools):
                res = _execute_single(i, t)
                if res:
                    results.append(res)
                if cancel_event and cancel_event.is_set():
                    break

        completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        total_duration = time.time() - t_start

        batch_result = BatchResult(
            job_id=job_id,
            input_target=plan.raw_input,
            input_type=plan.input_info["type"],
            workflow_name=f"Custom ({len(plan.tools)} tools)",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=total_duration,
            tool_results=results,
            skipped_tools=skipped,
        )

        # Record history
        self._record_history(batch_result)

        if on_log:
            on_log(f"[*] Batch '{job_id}' completed in {round(total_duration, 2)}s: {batch_result.successful_count} succeeded, {batch_result.failed_count} failed, {batch_result.skipped_count} skipped.")

        if job_id in self._active_cancellations:
            del self._active_cancellations[job_id]

        return batch_result

    def cancel_job(self, job_id: str) -> bool:
        """Signals cancellation to an active batch execution job."""
        event = self._active_cancellations.get(job_id)
        if event:
            event.set()
            return True
        return False

    # -------------------------------------------------------------------------
    # Saved Profiles / Tool Sets
    # -------------------------------------------------------------------------

    def list_saved_profiles(self) -> List[Dict[str, Any]]:
        """Lists user-saved custom tool set profiles along with system default workflows."""
        profiles: List[Dict[str, Any]] = []

        # System defaults
        for wid, wspec in PREDEFINED_WORKFLOWS.items():
            profiles.append({
                "id": f"system_{wid}",
                "name": wspec["name"],
                "description": wspec["description"],
                "is_system": True,
                "tool_count": len(wspec["tools"]),
                "tools": wspec["tools"],
            })

        # User custom sets
        if self._profiles_file.exists():
            try:
                with open(self._profiles_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("profiles", []):
                        item["is_system"] = False
                        profiles.append(item)
            except Exception:
                pass

        return profiles

    def save_custom_profile(self, name: str, description: str, tools: List[str]) -> Dict[str, Any]:
        """Saves a custom collection of tool binaries as a reusable profile."""
        pid = f"custom_{hashlib.sha256(name.encode()).hexdigest()[:8]}"
        existing = []
        if self._profiles_file.exists():
            try:
                with open(self._profiles_file, "r", encoding="utf-8") as f:
                    existing = json.load(f).get("profiles", [])
            except Exception:
                existing = []

        # Remove duplicate name if present
        existing = [p for p in existing if p.get("name", "").lower() != name.lower() and p.get("id") != pid]

        new_entry = {
            "id": pid,
            "name": name.strip(),
            "description": description.strip(),
            "tool_count": len(tools),
            "tools": tools,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        existing.append(new_entry)

        self._profiles_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._profiles_file, "w", encoding="utf-8") as f:
            json.dump({"profiles": existing}, f, indent=2)

        return new_entry

    def delete_custom_profile(self, profile_id: str) -> bool:
        """Deletes a user-saved custom profile by ID."""
        if not self._profiles_file.exists():
            return False

        try:
            with open(self._profiles_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            orig = data.get("profiles", [])
            filtered = [p for p in orig if p.get("id") != profile_id]
            if len(orig) == len(filtered):
                return False

            with open(self._profiles_file, "w", encoding="utf-8") as f:
                json.dump({"profiles": filtered}, f, indent=2)
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Batch History Log
    # -------------------------------------------------------------------------

    def list_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves past batch execution entries."""
        if not self._history_file.exists():
            return []
        try:
            with open(self._history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("history", [])[:limit]
        except Exception:
            return []

    def _record_history(self, res: BatchResult) -> None:
        """Appends a concise metadata record of a batch execution."""
        entry = {
            "job_id": res.job_id,
            "input_target": res.input_target,
            "input_type": res.input_type,
            "workflow_name": res.workflow_name,
            "started_at": res.started_at,
            "duration_seconds": round(res.duration_seconds, 2),
            "tools_run": res.total_tools_run,
            "successful": res.successful_count,
            "failed": res.failed_count,
            "skipped": res.skipped_count,
            "indicators_extracted": len(res.deduplicated_indicators),
            "findings_count": len(res.aggregated_findings),
        }

        history = []
        if self._history_file.exists():
            try:
                with open(self._history_file, "r", encoding="utf-8") as f:
                    history = json.load(f).get("history", [])
            except Exception:
                history = []

        history.insert(0, entry)
        history = history[:100]  # Cap at 100 entries

        try:
            self._history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._history_file, "w", encoding="utf-8") as f:
                json.dump({"history": history}, f, indent=2)
        except Exception:
            pass
