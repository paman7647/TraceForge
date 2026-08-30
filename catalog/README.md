# Central Tool Catalog Architecture

The file `catalog/tools.tsv` is the single source of truth for the entire TraceForge toolkit.
It indexes **175 thoroughly audited tools** across 13 dedicated investigation domains.

## Schema Specification

`catalog/tools.tsv` is a strict, tab-separated table with 22 columns:

```text
id  name    binary  category    subcategory ecosystem   mac_install linux_install   description status  requires_root   requires_api    requires_hardware   notes   source_url  termux_status   termux_package  termux_install  termux_notes    termux_root termux_api  termux_hardware
```

### Investigation Categories (13 Domains)
1. **Media & Image Forensics** (39 tools)
2. **Domain, DNS & Infrastructure Intelligence** (30 tools)
3. **Document & Metadata Harvesting** (20 tools)
4. **Network, PCAP & Wireless Forensics** (18 tools)
5. **OPSEC & Metadata Anonymization** (17 tools)
6. **Email, Breach & Leak Intelligence** (15 tools)
7. **Identity, Social & SOCMINT** (12 tools)
8. **Threat Intelligence & Passive DNS** (6 tools)
9. **Geospatial, Wireless & IoT Intelligence** (5 tools)
10. **Cloud & Attack Surface Exposure** (4 tools)
11. **Financial, Blockchain & Crypto OSINT** (4 tools)
12. **Public Records, Corporate & Darknet OSINT** (4 tools)
13. **First-Party Suite Native Tools** (1 tool)

