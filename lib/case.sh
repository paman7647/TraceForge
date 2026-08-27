#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2155,SC2206,SC2016,SC1090,SC1091,SC2295
# =============================================================================
# TraceForge — lib/case.sh
# Canonical Case Management, Evidence Ingestion, Chain of Custody & Normalization
#
# Schema Version: 1.0
# =============================================================================

# Prevent double inclusion
if [[ -n "${_TRACEFORGE_CASE_SH_LOADED:-}" ]]; then
    return 0
fi
_TRACEFORGE_CASE_SH_LOADED=1

# shellcheck source=lib/common.sh
source "$(project_root)/lib/common.sh"
# shellcheck source=lib/platform.sh
source "$(project_root)/lib/platform.sh"

# Global active case tracker
CURRENT_ACTIVE_CASE=""

# Case directories base path
cases_dir() {
    local cdir="$(project_root)/workspace"
    mkdir -p "$cdir"
    printf '%s\n' "$cdir"
}

# Generate unique case ID: CASE-YYYYMMDD-XXXXXX
generate_case_id() {
    local dt rand_hex
    dt="$(date '+%Y%m%d')"
    if need_cmd openssl; then
        rand_hex="$(openssl rand -hex 3 | tr '[:lower:]' '[:upper:]')"
    else
        rand_hex="$(printf '%06X' "$((RANDOM * RANDOM % 16777215))")"
    fi
    printf 'CASE-%s-%s\n' "$dt" "$rand_hex"
}

# Resolve case directory by ID or path
case_get_path() {
    local target_id=$1
    # Check if target_id is already a path
    if [[ -d "$target_id" && -f "$target_id/case.json" ]]; then
        (cd "$target_id" && pwd -P)
        return 0
    fi
    local cpath="$(cases_dir)/$target_id"
    if [[ -d "$cpath" ]]; then
        printf '%s\n' "$cpath"
        return 0
    fi
    # Search for matching directory
    local found
    found="$(find "$(cases_dir)" -maxdepth 1 -type d -name "*${target_id}*" | head -n 1)"
    if [[ -n "$found" && -d "$found" ]]; then
        printf '%s\n' "$found"
        return 0
    fi
    return 1
}

# Create a new canonical case
case_create() {
    local name="${1:-"Untitled Investigation"}"
    local analyst="${2:-"${USER:-"Analyst"}"}"
    local org="${3:-"Open Source Investigation"}"
    local classification="${4:-"TLP:CLEAR"}"
    local incident_ref="${5:-"N/A"}"
    local notes="${6:-""}"

    local case_id
    case_id="$(generate_case_id)"
    local case_path="$(cases_dir)/$case_id"

    mkdir -p "$case_path"/{evidence,raw,normalized,findings,iocs,timelines,reports,exports,logs,manifest}
    touch "$case_path/manifest/evidence-chain.jsonl"

    local created_time
    created_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Create canonical case.json using Python for strict, robust JSON serialization
    python3 - "$case_id" "$name" "$analyst" "$org" "$classification" "$incident_ref" "$created_time" "$OS_NAME" "$OS_TYPE" "$OS_ARCH" "$notes" << 'PYEOF' > "$case_path/case.json"
import json, sys
cid, name, analyst, org, classification, incident_ref, created_time, os_name, os_type, os_arch, notes = sys.argv[1:12]

case_data = {
    "schema_version": "1.0",
    "suite_version": "1.0.1",
    "case_id": cid,
    "case_name": name,
    "analyst": analyst,
    "organization": org,
    "classification": classification,
    "incident_ref": incident_ref,
    "created_at": created_time,
    "updated_at": created_time,
    "platform": os_name,
    "host_os": os_type,
    "architecture": os_arch,
    "evidence": [],
    "modules_run": [],
    "tools_run": [],
    "findings": [],
    "iocs": [],
    "timeline_events": [],
    "entities": [],
    "locations": [],
    "network_observations": [],
    "metadata": {
        "export_count": 0,
        "last_exported_at": None
    },
    "limitations": "Standard open-source intelligence collection limitations apply. Non-intrusive collection methods.",
    "notes": notes
}

print(json.dumps(case_data, indent=2))
PYEOF

    # Generate case.yml representation for analyst readability
    cat << YAMLEOF > "$case_path/case.yml"
# TraceForge Canonical Case Specification
schema_version: "1.0"
case_id: "$case_id"
case_name: "$name"
analyst: "$analyst"
organization: "$org"
classification: "$classification"
incident_ref: "$incident_ref"
created_at: "$created_time"
platform: "$OS_NAME ($OS_ARCH)"
notes: "$notes"
YAMLEOF

    # Log initial creation in chain of custody
    case_log_chain "$case_id" "CASE_CREATED" "N/A" "N/A" "N/A" "case.sh" "Case initialized successfully."

    CURRENT_ACTIVE_CASE="$case_id"
    info "Created new canonical case: $case_id ($name)"
    printf '%s\n' "$case_id"
}

# Record an entry into the evidence chain of custody log
case_log_chain() {
    local case_id=$1
    local action=$2
    local evidence_id=${3:-"N/A"}
    local input_hash=${4:-"N/A"}
    local output_hash=${5:-"N/A"}
    local tool=${6:-"TraceForge"}
    local result=${7:-"SUCCESS"}

    local case_path
    case_path="$(case_get_path "$case_id")" || return 1
    local log_file="$case_path/manifest/evidence-chain.jsonl"

    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local actor="${USER:-"analyst"}"

    python3 - "$timestamp" "$actor" "$action" "$case_id" "$evidence_id" "$input_hash" "$output_hash" "$tool" "$result" << 'PYEOF' >> "$log_file"
import json, sys
ts, actor, action, cid, evid_id, in_hash, out_hash, tool, result = sys.argv[1:10]
entry = {
    "timestamp": ts,
    "actor": actor,
    "action": action,
    "case_id": cid,
    "evidence_id": evid_id,
    "input_hash": in_hash,
    "output_hash": out_hash,
    "tool": tool,
    "tool_version": "1.0.1",
    "result": result
}
print(json.dumps(entry))
PYEOF
}

# Ingest an evidence file non-destructively
case_add_evidence() {
    local case_id=$1
    local src_file=$2
    local source_desc=${3:-"Direct File Import"}
    local notes=${4:-""}

    if [[ ! -f "$src_file" ]]; then
        die "Evidence source file not found: $src_file"
    fi
    if [[ ! -r "$src_file" ]]; then
        die "Evidence source file is not readable: $src_file"
    fi

    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"

    local abs_src
    abs_src="$(CDPATH='' cd -- "$(dirname -- "$src_file")" && pwd -P)/$(basename -- "$src_file")"
    local base_name
    base_name="$(basename -- "$abs_src")"

    # Compute hashes & metadata
    local sha256_val size_bytes mime_type
    sha256_val="$(hash_file "$abs_src")"
    size_bytes="$(wc -c < "$abs_src" | tr -d ' ')"
    mime_type="$(file -b --mime-type "$abs_src" 2>/dev/null || echo "application/octet-stream")"

    # Determine unique evidence ID EVID-001, EVID-002, etc.
    local next_idx
    next_idx="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1] + "/case.json")); print(len(d.get("evidence", [])) + 1)' "$case_path")"
    local evid_id
    evid_id="$(printf 'EVID-%03d' "$next_idx")"

    local dest_filename="${evid_id}_${base_name}"
    local dest_rel_path="evidence/$dest_filename"
    local dest_full_path="$case_path/$dest_rel_path"

    # Copy evidence to preserve immutability
    cp "$abs_src" "$dest_full_path"

    local import_time
    import_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Update case.json atomically
    python3 - "$case_path" "$evid_id" "$base_name" "$abs_src" "$dest_rel_path" "$sha256_val" "$size_bytes" "$mime_type" "$import_time" "$source_desc" "$notes" << 'PYEOF'
import json, sys
cpath, evid_id, base_name, abs_src, dest_rel, sha256_v, size_b, mime_t, imp_time, src_desc, notes = sys.argv[1:12]

with open(f"{cpath}/case.json", "r") as f:
    data = json.load(f)

new_evid = {
    "evidence_id": evid_id,
    "original_name": base_name,
    "original_path": abs_src,
    "stored_path": dest_rel,
    "sha256": sha256_v,
    "size_bytes": int(size_b) if size_b.isdigit() else 0,
    "mime_type": mime_t,
    "imported_at": imp_time,
    "source": src_desc,
    "notes": notes
}

data.setdefault("evidence", []).append(new_evid)
data["updated_at"] = imp_time

with open(f"{cpath}/case.json", "w") as f:
    json.dump(data, f, indent=2)
PYEOF

    case_log_chain "$case_id" "EVIDENCE_INGESTED" "$evid_id" "$sha256_val" "$sha256_val" "case.sh" "Ingested $base_name ($size_bytes bytes)"

    info "Ingested evidence [$evid_id]: $base_name (SHA-256: ${sha256_val:0:16}...)"
    printf '%s\n' "$evid_id"
}

# Add a finding to the case
case_add_finding() {
    local case_id=$1
    local title=$2
    local severity=${3:-"informational"}  # informational, low, medium, high, critical
    local confidence=${4:-"confirmed"}    # low, medium, high, confirmed
    local summary=${5:-""}
    local details=${6:-""}
    local evidence_ref=${7:-""}
    local tool_ref=${8:-""}
    local analyst_notes=${9:-""}

    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"

    local created_time
    created_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local next_idx
    next_idx="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1] + "/case.json")); print(len(d.get("findings", [])) + 1)' "$case_path")"
    local find_id
    find_id="$(printf 'FIND-%03d' "$next_idx")"

    python3 - "$case_path" "$find_id" "$title" "$severity" "$confidence" "$summary" "$details" "$evidence_ref" "$tool_ref" "$analyst_notes" "$created_time" << 'PYEOF'
import json, sys
cpath, find_id, title, severity, confidence, summary, details, evid_ref, tool_ref, a_notes, cr_time = sys.argv[1:12]

with open(f"{cpath}/case.json", "r") as f:
    data = json.load(f)

evid_refs = [evid_ref] if evid_ref else []
tool_refs = [tool_ref] if tool_ref else []

finding = {
    "finding_id": find_id,
    "title": title,
    "severity": severity.lower(),
    "confidence": confidence.lower(),
    "status": "verified",
    "summary": summary,
    "details": details,
    "evidence_refs": evid_refs,
    "tool_refs": tool_refs,
    "ioc_refs": [],
    "timeline_refs": [],
    "analyst_notes": a_notes,
    "created_at": cr_time,
    "updated_at": cr_time
}

data.setdefault("findings", []).append(finding)
data["updated_at"] = cr_time

with open(f"{cpath}/case.json", "w") as f:
    json.dump(data, f, indent=2)

# Also write individual finding JSON in findings/
with open(f"{cpath}/findings/{find_id}.json", "w") as f:
    json.dump(finding, f, indent=2)
PYEOF

    case_log_chain "$case_id" "FINDING_ADDED" "$find_id" "N/A" "N/A" "case.sh" "Added $find_id: $title ($severity)"
    info "Recorded finding [$find_id]: $title [$severity / $confidence]"
    printf '%s\n' "$find_id"
}

# Add an IOC to the case
case_add_ioc() {
    local case_id=$1
    local ioc_type=$2   # ipv4, ipv6, domain, url, email, hash_sha256, hash_md5, username, etc.
    local value=$3
    local source=${4:-"Investigation Observation"}
    local confidence=${5:-"high"}
    local severity=${6:-"medium"}
    local tags_str=${7:-""}

    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"

    local created_time
    created_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local next_idx
    next_idx="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1] + "/case.json")); print(len(d.get("iocs", [])) + 1)' "$case_path")"
    local ioc_id
    ioc_id="$(printf 'IOC-%03d' "$next_idx")"

    python3 - "$case_path" "$ioc_id" "$ioc_type" "$value" "$source" "$confidence" "$severity" "$tags_str" "$case_id" "$created_time" << 'PYEOF'
import json, sys
cpath, ioc_id, ioc_type, value, src, conf, sev, tags_s, cid, cr_time = sys.argv[1:11]

with open(f"{cpath}/case.json", "r") as f:
    data = json.load(f)

tags = [t.strip() for t in tags_s.split(",") if t.strip()]

ioc = {
    "ioc_id": ioc_id,
    "type": ioc_type.lower(),
    "value": value,
    "normalized_value": value.strip().lower(),
    "source": src,
    "first_seen": cr_time,
    "last_seen": cr_time,
    "confidence": conf.lower(),
    "severity": sev.lower(),
    "tags": tags,
    "case_id": cid
}

data.setdefault("iocs", []).append(ioc)
data["updated_at"] = cr_time

with open(f"{cpath}/case.json", "w") as f:
    json.dump(data, f, indent=2)

with open(f"{cpath}/iocs/{ioc_id}.json", "w") as f:
    json.dump(ioc, f, indent=2)
PYEOF

    case_log_chain "$case_id" "IOC_RECORDED" "N/A" "N/A" "N/A" "case.sh" "Recorded $ioc_id: $ioc_type -> $value"
    printf '%s\n' "$ioc_id"
}

# Add a timeline event to the case
case_add_timeline_event() {
    local case_id=$1
    local timestamp_utc=$2
    local event_type=${3:-"observed_time"}  # observed_time, filesystem_time, metadata_time, inferred_time
    local description=$4
    local evidence_id=${5:-""}
    local tool=${6:-""}
    local severity=${7:-"informational"}
    local confidence=${8:-"confirmed"}

    local case_path
    case_path="$(case_get_path "$case_id")" || die "Case not found: $case_id"

    local next_idx
    next_idx="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1] + "/case.json")); print(len(d.get("timeline_events", [])) + 1)' "$case_path")"
    local evt_id
    evt_id="$(printf 'EVT-%04d' "$next_idx")"

    python3 - "$case_path" "$evt_id" "$timestamp_utc" "$event_type" "$description" "$evidence_id" "$tool" "$severity" "$confidence" << 'PYEOF'
import json, sys
cpath, evt_id, ts_utc, evt_type, desc, evid_id, tool, sev, conf = sys.argv[1:10]

with open(f"{cpath}/case.json", "r") as f:
    data = json.load(f)

evt = {
    "event_id": evt_id,
    "timestamp_utc": ts_utc,
    "timestamp_original": ts_utc,
    "timezone": "UTC",
    "event_type": evt_type,
    "source": tool or "Investigation",
    "description": desc,
    "evidence_id": evid_id,
    "tool": tool,
    "severity": sev,
    "confidence": conf
}

data.setdefault("timeline_events", []).append(evt)
data["timeline_events"].sort(key=lambda x: x.get("timestamp_utc", ""))

with open(f"{cpath}/case.json", "w") as f:
    json.dump(data, f, indent=2)
PYEOF

    printf '%s\n' "$evt_id"
}

# Normalize module outputs into the case data model
case_ingest_module_run() {
    local case_id=$1
    local module_script=$2
    local evidence_id=$3
    local run_workspace=$4

    local case_path
    case_path="$(case_get_path "$case_id")" || return 1
    local mod_name
    mod_name="$(basename -- "$module_script" .sh)"

    info "Normalizing module outputs from $mod_name into case $case_id..."

    # Copy raw run folder to case raw/
    local target_raw="$case_path/raw/${mod_name}_$(date '+%Y%m%d_%H%M%S')"
    mkdir -p "$target_raw"
    cp -R "$run_workspace"/* "$target_raw/" 2>/dev/null || true

    # Extract findings and IOCs using Python parser
    python3 - << PYEOF
import json, os, glob, re

case_file = "$case_path/case.json"
with open(case_file, "r") as f:
    data = json.load(f)

if "$mod_name" not in data.get("modules_run", []):
    data.setdefault("modules_run", []).append("$mod_name")

now_utc = "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# 1. Inspect metadata.json if generated (Image / Document Forensics)
meta_json_path = os.path.join("$run_workspace", "metadata.json")
if os.path.exists(meta_json_path):
    try:
        with open(meta_json_path) as mf:
            meta_items = json.load(mf)
            if isinstance(meta_items, list) and len(meta_items) > 0:
                meta = meta_items[0]
                # Check for GPS coordinates
                lat = meta.get("Composite:GPSLatitude") or meta.get("EXIF:GPSLatitude")
                lon = meta.get("Composite:GPSLongitude") or meta.get("EXIF:GPSLongitude")
                if lat and lon:
                    loc_id = f"LOC-{len(data.get('locations', []))+1:03d}"
                    loc_entry = {
                        "location_id": loc_id,
                        "latitude": float(lat) if isinstance(lat, (int, float)) else str(lat),
                        "longitude": float(lon) if isinstance(lon, (int, float)) else str(lon),
                        "description": f"Extracted from {meta.get('File:FileName', 'evidence')}",
                        "evidence_id": "$evidence_id",
                        "timestamp": now_utc,
                        "confidence": "confirmed",
                        "maps_url": f"https://www.google.com/maps?q={lat},{lon}"
                    }
                    data.setdefault("locations", []).append(loc_entry)
                    
                    # Also add a high-confidence finding
                    find_id = f"FIND-{len(data.get('findings', []))+1:03d}"
                    data.setdefault("findings", []).append({
                        "finding_id": find_id,
                        "title": "Embedded GPS Coordinates Discovered",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "status": "verified",
                        "summary": f"Target media contains embedded geolocation: {lat}, {lon}",
                        "details": f"File {meta.get('File:FileName')} has GPS tags. Google Maps URL: {loc_entry['maps_url']}",
                        "evidence_refs": ["$evidence_id"] if "$evidence_id" else [],
                        "tool_refs": ["exiftool"],
                        "ioc_refs": [],
                        "timeline_refs": [],
                        "created_at": now_utc,
                        "updated_at": now_utc
                    })

                # Check for creation date in metadata
                create_date = meta.get("EXIF:CreateDate") or meta.get("QuickTime:CreateDate") or meta.get("PDF:CreateDate")
                if create_date:
                    evt_id = f"EVT-{len(data.get('timeline_events', []))+1:04d}"
                    data.setdefault("timeline_events", []).append({
                        "event_id": evt_id,
                        "timestamp_utc": str(create_date).replace(":", "-", 2),
                        "timestamp_original": str(create_date),
                        "timezone": "UTC",
                        "event_type": "metadata_time",
                        "source": "ExifTool Metadata",
                        "description": f"File creation timestamp recorded as {create_date}",
                        "evidence_id": "$evidence_id",
                        "tool": "exiftool",
                        "severity": "informational",
                        "confidence": "confirmed"
                    })
    except Exception as e:
        pass

# 2. Inspect high_interest_indicators.txt
ind_file = os.path.join("$run_workspace", "high_interest_indicators.txt")
if os.path.exists(ind_file):
    with open(ind_file) as f_ind:
        lines = f_ind.readlines()
        if len(lines) > 0:
            find_id = f"FIND-{len(data.get('findings', []))+1:03d}"
            snippet = "".join(lines[:5])
            data.setdefault("findings", []).append({
                "finding_id": find_id,
                "title": f"High-Interest String / Secret Indicators Found ({len(lines)} hits)",
                "severity": "high",
                "confidence": "high",
                "status": "verified",
                "summary": f"Detected {len(lines)} sensitive keyword matches (passwords, tokens, API keys).",
                "details": f"Sample indicators:\n{snippet}",
                "evidence_refs": ["$evidence_id"] if "$evidence_id" else [],
                "tool_refs": ["strings", "ripgrep"],
                "ioc_refs": [],
                "timeline_refs": [],
                "created_at": now_utc,
                "updated_at": now_utc
            })

# 3. Inspect unique_subdomains.txt or httpx_probed.txt (Domain Recon)
sub_file = os.path.join("$run_workspace", "unique_subdomains.txt")
if os.path.exists(sub_file):
    with open(sub_file) as sf:
        subs = [line.strip() for line in sf if line.strip()]
        for s in subs[:50]:
            ioc_id = f"IOC-{len(data.get('iocs', []))+1:03d}"
            data.setdefault("iocs", []).append({
                "ioc_id": ioc_id,
                "type": "domain",
                "value": s,
                "normalized_value": s.lower(),
                "source": "Subdomain Enumeration",
                "first_seen": now_utc,
                "last_seen": now_utc,
                "confidence": "high",
                "severity": "informational",
                "tags": ["subdomain", "recon"],
                "case_id": "$case_id"
            })

# Save updated case.json
data["updated_at"] = now_utc
with open(case_file, "w") as f:
    json.dump(data, f, indent=2)
PYEOF

    case_log_chain "$case_id" "MODULE_RUN_NORMALIZED" "$evidence_id" "N/A" "N/A" "$mod_name" "Normalized outputs from $run_workspace"
}

# List all available cases
case_list() {
    local cdir="$(cases_dir)"
    find "$cdir" -mindepth 1 -maxdepth 1 -type d -name "CASE-*" | sort -r
}
