# Third-Party Software Notices & Attribution

```text
TraceForge
Copyright (c) 2026 Aman Kumar Pandey
Licensed under the MIT License.
```

Third-party software remains the property of its respective authors and is used according to its own license and terms.

> **Important License Boundary:** The MIT License for TraceForge does **not** relicense third-party utilities included in the catalog or installed by the installer. Each upstream project retains its own licensing terms and copyright ownership.

TraceForge is an open-source command-line toolkit, tool catalog, case manager, and automated package provisioner. It coordinates and launches independent third-party command-line utilities developed by the open-source security, OSINT, and digital forensics community.

---

## 1. Architecture: Toolkit vs. External Utilities

```text
+-------------------------------------------------------------------+
|                            TraceForge                             |
|      (Framework, CLI Menu, Case Management, Forensic Reporting)   |
|                         [ MIT License ]                           |
+---------------------------------+---------------------------------+
                                  |
                                  | Installs / Invokes / Normalizes
                                  v
+-------------------------------------------------------------------+
|                 Independent Third-Party Utilities                 |
|   (ExifTool, TShark, Binwalk, Nmap, Sherlock, Maigret, etc.)     |
|         [ Retain Respective Upstream Copyright & Licenses ]        |
+-------------------------------------------------------------------+
```

* **No Proprietary Bundling**: TraceForge does not ship pre-compiled third-party binaries or vendored copies of external source trees inside this repository.
* **Native Ecosystem Installation**: Utilities are installed directly from official upstream package repositories (Homebrew, APT, PyPI via isolated `pipx` or virtual environments, Go modules, RubyGems, Cargo crates).
* **Independent Ownership**: Each external utility is governed by its own license terms, upstream documentation, and service restrictions. TraceForge does not modify or supersede those terms.

---

## 2. Upstream Tool Catalog & Licensing Index

The following table details the verified upstream source URLs and license models for all utilities indexed in the TraceForge catalog:

| ID | Tool Name | Binary | Category | Ecosystem | Upstream Source / Repository | License |
|---|---|---|---|---|---|---|
| 1 | **ExifTool** | `exiftool` | Media & Image Forensics | `native` | [https://github.com/exiftool/exiftool](https://github.com/exiftool/exiftool) | Artistic-1.0 / GPL-1.0+ |
| 2 | **Binwalk** | `binwalk` | Media & Image Forensics | `native` | [https://github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) | MIT |
| 3 | **xxd** | `xxd` | Media & Image Forensics | `native` | [https://github.com/vim/vim](https://github.com/vim/vim) | Open Source (Refer to upstream) |
| 4 | **zsteg** | `zsteg` | Media & Image Forensics | `ruby_gem` | [https://github.com/zed-0xff/zsteg](https://github.com/zed-0xff/zsteg) | MIT |
| 5 | **Steghide** | `steghide` | Media & Image Forensics | `native` | [https://github.com/StefanoDeVuono/steghide](https://github.com/StefanoDeVuono/steghide) | GPL-2.0 |
| 6 | **Stegseek** | `stegseek` | Media & Image Forensics | `native` | [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek) | Open Source (Refer to upstream) |
| 7 | **jhead** | `jhead` | Media & Image Forensics | `native` | [https://github.com/Matthias-Wandel/jhead](https://github.com/Matthias-Wandel/jhead) | Open Source (Refer to upstream) |
| 8 | **pngcheck** | `pngcheck` | Media & Image Forensics | `native` | [http://www.libpng.org/pub/png/apps/pngcheck.html](http://www.libpng.org/pub/png/apps/pngcheck.html) | GPL-2.0+ |
| 9 | **jpeginfo** | `jpeginfo` | Media & Image Forensics | `native` | [https://github.com/tjko/jpeginfo](https://github.com/tjko/jpeginfo) | Open Source (Refer to upstream) |
| 10 | **ImageMagick** | `magick` | Media & Image Forensics | `native` | [https://github.com/ImageMagick/ImageMagick](https://github.com/ImageMagick/ImageMagick) | ImageMagick License (Apache-2.0 compatible) |
| 11 | **GraphicsMagick** | `gm` | Media & Image Forensics | `native` | [http://www.graphicsmagick.org/](http://www.graphicsmagick.org/) | Open Source (Refer to upstream) |
| 12 | **Exiv2** | `exiv2` | Media & Image Forensics | `native` | [https://github.com/Exiv2/exiv2](https://github.com/Exiv2/exiv2) | GPL-2.0+ |
| 13 | **FFmpeg** | `ffmpeg` | Media & Image Forensics | `native` | [https://github.com/FFmpeg/FFmpeg](https://github.com/FFmpeg/FFmpeg) | LGPL-2.1+ / GPL-2.0+ |
| 14 | **FFprobe** | `ffprobe` | Media & Image Forensics | `native` | [https://github.com/FFmpeg/FFmpeg](https://github.com/FFmpeg/FFmpeg) | Open Source (Refer to upstream) |
| 15 | **Foremost** | `foremost` | Media & Image Forensics | `native` | [https://github.com/korczis/foremost](https://github.com/korczis/foremost) | Public Domain |
| 16 | **Scalpel** | `scalpel` | Media & Image Forensics | `native` | [https://github.com/sleuthkit/scalpel](https://github.com/sleuthkit/scalpel) | Open Source (Refer to upstream) |
| 17 | **bulk_extractor** | `bulk_extractor` | Media & Image Forensics | `native` | [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor) | Open Source (Refer to upstream) |
| 18 | **PhotoRec** | `photorec` | Media & Image Forensics | `native` | [https://github.com/cgsecurity/testdisk](https://github.com/cgsecurity/testdisk) | Open Source (Refer to upstream) |
| 19 | **TestDisk** | `testdisk` | Media & Image Forensics | `native` | [https://github.com/cgsecurity/testdisk](https://github.com/cgsecurity/testdisk) | Open Source (Refer to upstream) |
| 20 | **YARA** | `yara` | Media & Image Forensics | `native` | [https://github.com/VirusTotal/yara](https://github.com/VirusTotal/yara) | Open Source (Refer to upstream) |
| 21 | **Tesseract OCR** | `tesseract` | Media & Image Forensics | `native` | [https://github.com/tesseract-ocr/tesseract](https://github.com/tesseract-ocr/tesseract) | Apache-2.0 |
| 22 | **GPSBabel** | `gpsbabel` | Media & Image Forensics | `native` | [https://github.com/gpsbabel/gpsbabel](https://github.com/gpsbabel/gpsbabel) | Open Source (Refer to upstream) |
| 23 | **GDAL Info** | `gdalinfo` | Media & Image Forensics | `native` | [https://github.com/OSGeo/gdal](https://github.com/OSGeo/gdal) | Open Source (Refer to upstream) |
| 24 | **MediaInfo** | `mediainfo` | Media & Image Forensics | `native` | [https://github.com/MediaArea/MediaInfo](https://github.com/MediaArea/MediaInfo) | Open Source (Refer to upstream) |
| 25 | **yt-dlp** | `yt-dlp` | Media & Image Forensics | `pipx` | [https://github.com/yt-dlp/yt-dlp](https://github.com/yt-dlp/yt-dlp) | Open Source (Refer to upstream) |
| 26 | **gallery-dl** | `gallery-dl` | Media & Image Forensics | `pipx` | [https://github.com/mikf/gallery-dl](https://github.com/mikf/gallery-dl) | Open Source (Refer to upstream) |
| 27 | **OCRmyPDF** | `ocrmypdf` | Media & Image Forensics | `pipx` | [https://github.com/ocrmypdf/OCRmyPDF](https://github.com/ocrmypdf/OCRmyPDF) | Open Source (Refer to upstream) |
| 28 | **ZBar** | `zbarimg` | Media & Image Forensics | `native` | [https://github.com/mchehab/zbar](https://github.com/mchehab/zbar) | Open Source (Refer to upstream) |
| 29 | **Hachoir Metadata** | `hachoir-metadata` | Media & Image Forensics | `pipx` | [https://github.com/vstinner/hachoir](https://github.com/vstinner/hachoir) | Open Source (Refer to upstream) |
| 30 | **WebP Tools** | `cwebp` | Media & Image Forensics | `native` | [https://chromium.googlesource.com/webm/libwebp](https://chromium.googlesource.com/webm/libwebp) | Open Source (Refer to upstream) |
| 31 | **AVIF Tools** | `avifdec` | Media & Image Forensics | `native` | [https://github.com/AOMediaCodec/libavif](https://github.com/AOMediaCodec/libavif) | Open Source (Refer to upstream) |
| 32 | **HEIF Tools** | `heif-convert` | Media & Image Forensics | `native` | [https://github.com/strukturag/libheif](https://github.com/strukturag/libheif) | Open Source (Refer to upstream) |
| 33 | **Osmium Tool** | `osmium` | Media & Image Forensics | `native` | [https://github.com/osmcode/osmium-tool](https://github.com/osmcode/osmium-tool) | Open Source (Refer to upstream) |
| 34 | **OutGuess** | `outguess` | Media & Image Forensics | `native` | [https://github.com/resurrecting-open-source-projects/outguess](https://github.com/resurrecting-open-source-projects/outguess) | BSD-3-Clause |
| 35 | **Sherlock** | `sherlock` | Identity, Social & SOCMINT | `pipx` | [https://github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) | MIT |
| 36 | **Maigret** | `maigret` | Identity, Social & SOCMINT | `pipx` | [https://github.com/soxoj/maigret](https://github.com/soxoj/maigret) | MIT |
| 37 | **Blackbird** | `blackbird` | Identity, Social & SOCMINT | `pipx` | [https://github.com/p1ngul1n0/blackbird](https://github.com/p1ngul1n0/blackbird) | GPL-3.0 |
| 38 | **Socialscan** | `socialscan` | Identity, Social & SOCMINT | `pipx` | [https://github.com/iojw/socialscan](https://github.com/iojw/socialscan) | MIT |
| 39 | **sn0int** | `sn0int` | Identity, Social & SOCMINT | `cargo` | [https://github.com/kpcyrd/sn0int](https://github.com/kpcyrd/sn0int) | Open Source (Refer to upstream) |
| 40 | **Recon-ng** | `recon-ng` | Identity, Social & SOCMINT | `native` | [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) | Open Source (Refer to upstream) |
| 41 | **SpiderFoot** | `spiderfoot` | Identity, Social & SOCMINT | `pipx` | [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | Open Source (Refer to upstream) |
| 42 | **Twarc** | `twarc2` | Identity, Social & SOCMINT | `pipx` | [https://github.com/DocNow/twarc](https://github.com/DocNow/twarc) | Open Source (Refer to upstream) |
| 43 | **Snscrape** | `snscrape` | Identity, Social & SOCMINT | `pipx` | [https://github.com/JustAnotherArchivist/snscrape](https://github.com/JustAnotherArchivist/snscrape) | Open Source (Refer to upstream) |
| 44 | **Snoop** | `snoop` | Identity, Social & SOCMINT | `manual` | [https://github.com/snooppr/snoop](https://github.com/snooppr/snoop) | Open Source (Refer to upstream) |
| 45 | **WhatsMyName** | `whatsmyname` | Identity, Social & SOCMINT | `manual` | [https://github.com/WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | Open Source (Refer to upstream) |
| 46 | **DiscordChatExporter** | `DiscordChatExporter-CLI` | Identity, Social & SOCMINT | `manual` | [https://github.com/Tyrrrz/DiscordChatExporter](https://github.com/Tyrrrz/DiscordChatExporter) | Open Source (Refer to upstream) |
| 47 | **Holehe** | `holehe` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/megadose/holehe](https://github.com/megadose/holehe) | MIT |
| 48 | **h8mail** | `h8mail` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/khast3x/h8mail](https://github.com/khast3x/h8mail) | MIT |
| 49 | **theHarvester** | `theHarvester` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) | GPL-2.0 |
| 50 | **GHunt** | `ghunt` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/mxrch/GHunt](https://github.com/mxrch/GHunt) | GPL-3.0 |
| 51 | **EmailRep** | `emailrep` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/sublime-security/emailrep.io-python](https://github.com/sublime-security/emailrep.io-python) | Open Source (Refer to upstream) |
| 52 | **Gitleaks** | `gitleaks` | Email, Breach & Leak Intelligence | `native` | [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | Open Source (Refer to upstream) |
| 53 | **TruffleHog** | `trufflehog` | Email, Breach & Leak Intelligence | `native` | [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | Open Source (Refer to upstream) |
| 54 | **GitGuardian Shield** | `ggshield` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/GitGuardian/ggshield](https://github.com/GitGuardian/ggshield) | Open Source (Refer to upstream) |
| 55 | **CeWL** | `cewl` | Email, Breach & Leak Intelligence | `ruby_gem` | [https://github.com/digininja/CeWL](https://github.com/digininja/CeWL) | Open Source (Refer to upstream) |
| 56 | **John the Ripper** | `john` | Email, Breach & Leak Intelligence | `native` | [https://github.com/openwall/john](https://github.com/openwall/john) | Open Source (Refer to upstream) |
| 57 | **Hashcat** | `hashcat` | Email, Breach & Leak Intelligence | `native` | [https://github.com/hashcat/hashcat](https://github.com/hashcat/hashcat) | Open Source (Refer to upstream) |
| 58 | **Intelligence X CLI** | `intelx` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/IntelligenceX/SDK](https://github.com/IntelligenceX/SDK) | Open Source (Refer to upstream) |
| 59 | **TShark** | `tshark` | Network, PCAP & Wireless Forensics | `native` | [https://gitlab.com/wireshark/wireshark](https://gitlab.com/wireshark/wireshark) | GPL-2.0+ |
| 60 | **Capinfos** | `capinfos` | Network, PCAP & Wireless Forensics | `native` | [https://gitlab.com/wireshark/wireshark](https://gitlab.com/wireshark/wireshark) | Open Source (Refer to upstream) |
| 61 | **Editcap** | `editcap` | Network, PCAP & Wireless Forensics | `native` | [https://gitlab.com/wireshark/wireshark](https://gitlab.com/wireshark/wireshark) | GPL-2.0+ |
| 62 | **Mergecap** | `mergecap` | Network, PCAP & Wireless Forensics | `native` | [https://gitlab.com/wireshark/wireshark](https://gitlab.com/wireshark/wireshark) | GPL-2.0+ |
| 63 | **tcpdump** | `tcpdump` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump) | BSD-3-Clause |
| 64 | **Nmap** | `nmap` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/nmap/nmap](https://github.com/nmap/nmap) | Nmap Public Source License (NPSL) / GPL-2.0 |
| 65 | **Masscan** | `masscan` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) | AGPL-3.0 |
| 66 | **RustScan** | `rustscan` | Network, PCAP & Wireless Forensics | `cargo` | [https://github.com/RustScan/RustScan](https://github.com/RustScan/RustScan) | GPL-3.0 |
| 67 | **Aircrack-NG** | `aircrack-ng` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) | Open Source (Refer to upstream) |
| 68 | **hcxpcapngtool** | `hcxpcapngtool` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/ZerBea/hcxtools](https://github.com/ZerBea/hcxtools) | MIT |
| 69 | **Zeek** | `zeek` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/zeek/zeek](https://github.com/zeek/zeek) | BSD-3-Clause |
| 70 | **Suricata** | `suricata` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/OISF/suricata](https://github.com/OISF/suricata) | Open Source (Refer to upstream) |
| 71 | **arp-scan** | `arp-scan` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/royhills/arp-scan](https://github.com/royhills/arp-scan) | Open Source (Refer to upstream) |
| 72 | **Netdiscover** | `netdiscover` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/netdiscover-scanner/netdiscover](https://github.com/netdiscover-scanner/netdiscover) | Open Source (Refer to upstream) |
| 73 | **hping3** | `hping3` | Network, PCAP & Wireless Forensics | `native` | [https://github.com/antirez/hping](https://github.com/antirez/hping) | Open Source (Refer to upstream) |
| 74 | **Mitmproxy** | `mitmproxy` | Network, PCAP & Wireless Forensics | `pipx` | [https://github.com/mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) | Open Source (Refer to upstream) |
| 75 | **Subfinder** | `subfinder` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | MIT |
| 76 | **Amass** | `amass` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) | Apache-2.0 |
| 77 | **Assetfinder** | `assetfinder` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) | MIT |
| 78 | **dnsx** | `dnsx` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) | Open Source (Refer to upstream) |
| 79 | **httpx** | `httpx` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | Open Source (Refer to upstream) |
| 80 | **Naabu** | `naabu` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) | MIT |
| 81 | **Katana** | `katana` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana) | Open Source (Refer to upstream) |
| 82 | **Nuclei** | `nuclei` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Open Source (Refer to upstream) |
| 83 | **Uncover** | `uncover` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/uncover](https://github.com/projectdiscovery/uncover) | Open Source (Refer to upstream) |
| 84 | **Notify** | `notify` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/notify](https://github.com/projectdiscovery/notify) | Open Source (Refer to upstream) |
| 85 | **GAU** | `gau` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/lc/gau](https://github.com/lc/gau) | Open Source (Refer to upstream) |
| 86 | **Waybackurls** | `waybackurls` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) | Open Source (Refer to upstream) |
| 87 | **Gowitness** | `gowitness` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/sensepost/gowitness](https://github.com/sensepost/gowitness) | Open Source (Refer to upstream) |
| 88 | **dig** | `dig` | Domain, DNS & Infrastructure Intelligence | `native` | [https://gitlab.isc.org/isc-projects/bind9](https://gitlab.isc.org/isc-projects/bind9) | Open Source (Refer to upstream) |
| 89 | **whois** | `whois` | Domain, DNS & Infrastructure Intelligence | `native` | [https://github.com/rfc1036/whois](https://github.com/rfc1036/whois) | Open Source (Refer to upstream) |
| 90 | **DNSRecon** | `dnsrecon` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) | GPL-2.0 |
| 91 | **dnstwist** | `dnstwist` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/elceef/dnstwist](https://github.com/elceef/dnstwist) | GPL-3.0 |
| 92 | **WafW00f** | `wafw00f` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f) | Open Source (Refer to upstream) |
| 93 | **Prowler** | `prowler` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | Open Source (Refer to upstream) |
| 94 | **Shodan CLI** | `shodan` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/achillean/shodan-python](https://github.com/achillean/shodan-python) | Open Source (Refer to upstream) |
| 95 | **Censys CLI** | `censys` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/censys/censys-python](https://github.com/censys/censys-python) | Open Source (Refer to upstream) |
| 96 | **S3Scanner** | `s3scanner` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner) | Open Source (Refer to upstream) |
| 97 | **MapCIDR** | `mapcidr` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/mapcidr](https://github.com/projectdiscovery/mapcidr) | Open Source (Refer to upstream) |
| 98 | **ASNmap** | `asnmap` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap) | Open Source (Refer to upstream) |
| 99 | **CDNcheck** | `cdncheck` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) | Open Source (Refer to upstream) |
| 100 | **TLSx** | `tlsx` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx) | Open Source (Refer to upstream) |
| 101 | **pdfinfo** | `pdfinfo` | Document & Metadata Harvesting | `native` | [https://poppler.freedesktop.org/](https://poppler.freedesktop.org/) | Open Source (Refer to upstream) |
| 102 | **pdftotext** | `pdftotext` | Document & Metadata Harvesting | `native` | [https://poppler.freedesktop.org/](https://poppler.freedesktop.org/) | GPL-2.0+ |
| 103 | **pdfimages** | `pdfimages` | Document & Metadata Harvesting | `native` | [https://poppler.freedesktop.org/](https://poppler.freedesktop.org/) | GPL-2.0+ |
| 104 | **QPDF** | `qpdf` | Document & Metadata Harvesting | `native` | [https://github.com/qpdf/qpdf](https://github.com/qpdf/qpdf) | Apache-2.0 |
| 105 | **MuPDF mutool** | `mutool` | Document & Metadata Harvesting | `native` | [https://mupdf.com/](https://mupdf.com/) | AGPL-3.0 |
| 106 | **Ripgrep** | `rg` | Document & Metadata Harvesting | `native` | [https://github.com/BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | Open Source (Refer to upstream) |
| 107 | **fd** | `fd` | Document & Metadata Harvesting | `native` | [https://github.com/sharkdp/fd](https://github.com/sharkdp/fd) | Open Source (Refer to upstream) |
| 108 | **jq** | `jq` | Document & Metadata Harvesting | `native` | [https://github.com/jqlang/jq](https://github.com/jqlang/jq) | MIT |
| 109 | **olevba** | `olevba` | Document & Metadata Harvesting | `pipx` | [https://github.com/decalage2/oletools](https://github.com/decalage2/oletools) | Open Source (Refer to upstream) |
| 110 | **oleid** | `oleid` | Document & Metadata Harvesting | `pipx` | [https://github.com/decalage2/oletools](https://github.com/decalage2/oletools) | Open Source (Refer to upstream) |
| 111 | **olemeta** | `olemeta` | Document & Metadata Harvesting | `pipx` | [https://github.com/decalage2/oletools](https://github.com/decalage2/oletools) | Open Source (Refer to upstream) |
| 112 | **docx2txt** | `docx2txt` | Document & Metadata Harvesting | `native` | [https://docx2txt.sourceforge.net/](https://docx2txt.sourceforge.net/) | GPL-3.0 |
| 113 | **Antiword** | `antiword` | Document & Metadata Harvesting | `native` | [http://www.winfield.demon.nl/](http://www.winfield.demon.nl/) | GPL-2.0 |
| 114 | **Catdoc** | `catdoc` | Document & Metadata Harvesting | `native` | [https://www.wagner.pp.ru/~vitus/software/catdoc/](https://www.wagner.pp.ru/~vitus/software/catdoc/) | GPL-2.0 |
| 115 | **Pandoc** | `pandoc` | Document & Metadata Harvesting | `native` | [https://github.com/jgm/pandoc](https://github.com/jgm/pandoc) | Open Source (Refer to upstream) |
| 116 | **PeePDF** | `peepdf` | Document & Metadata Harvesting | `manual` | [https://github.com/jesparza/peepdf](https://github.com/jesparza/peepdf) | Open Source (Refer to upstream) |
| 117 | **PDFiD** | `pdfid` | Document & Metadata Harvesting | `manual` | [https://github.com/DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) | Open Source (Refer to upstream) |
| 118 | **MAT2** | `mat2` | OPSEC & Metadata Anonymization | `native` | [https://0xacab.org/jvoisin/mat2](https://0xacab.org/jvoisin/mat2) | LGPL-3.0+ |
| 119 | **Proxychains-NG** | `proxychains4` | OPSEC & Metadata Anonymization | `native` | [https://github.com/rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng) | Open Source (Refer to upstream) |
| 120 | **Tor** | `tor` | OPSEC & Metadata Anonymization | `native` | [https://gitlab.torproject.org/tpo/core/tor](https://gitlab.torproject.org/tpo/core/tor) | BSD-3-Clause |
| 121 | **torsocks** | `torsocks` | OPSEC & Metadata Anonymization | `native` | [https://gitlab.torproject.org/tpo/core/torsocks](https://gitlab.torproject.org/tpo/core/torsocks) | GPL-2.0 |
| 122 | **macchanger** | `macchanger` | OPSEC & Metadata Anonymization | `native` | [https://github.com/alobbs/macchanger](https://github.com/alobbs/macchanger) | GPL-3.0 |
| 123 | **WireGuard** | `wg` | OPSEC & Metadata Anonymization | `native` | [https://git.zx2c4.com/wireguard-tools/](https://git.zx2c4.com/wireguard-tools/) | Open Source (Refer to upstream) |
| 124 | **Privoxy** | `privoxy` | OPSEC & Metadata Anonymization | `native` | [https://www.privoxy.org/](https://www.privoxy.org/) | Open Source (Refer to upstream) |
| 125 | **Cloudflared** | `cloudflared` | OPSEC & Metadata Anonymization | `native` | [https://github.com/cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) | Apache-2.0 |
| 126 | **dnscrypt-proxy** | `dnscrypt-proxy` | OPSEC & Metadata Anonymization | `native` | [https://github.com/DNSCrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) | ISC |
| 127 | **Stubby** | `stubby` | OPSEC & Metadata Anonymization | `native` | [https://github.com/getdnsapi/stubby](https://github.com/getdnsapi/stubby) | Open Source (Refer to upstream) |
| 128 | **OpenSSH** | `ssh` | OPSEC & Metadata Anonymization | `native` | [https://www.openssh.com/](https://www.openssh.com/) | Open Source (Refer to upstream) |
| 129 | **socat** | `socat` | OPSEC & Metadata Anonymization | `native` | [http://www.dest-unreach.org/socat/](http://www.dest-unreach.org/socat/) | GPL-2.0 |
| 130 | **Ncat** | `ncat` | OPSEC & Metadata Anonymization | `native` | [https://nmap.org/ncat/](https://nmap.org/ncat/) | NPSL / GPL-2.0 |
| 131 | **GnuPG** | `gpg` | OPSEC & Metadata Anonymization | `native` | [https://gnupg.org/](https://gnupg.org/) | Open Source (Refer to upstream) |
| 132 | **age** | `age` | OPSEC & Metadata Anonymization | `native` | [https://github.com/FiloSottile/age](https://github.com/FiloSottile/age) | Open Source (Refer to upstream) |
| 133 | **OpenSSL** | `openssl` | OPSEC & Metadata Anonymization | `native` | [https://github.com/openssl/openssl](https://github.com/openssl/openssl) | Open Source (Refer to upstream) |
| 134 | **Secure Delete (srm)** | `srm` | OPSEC & Metadata Anonymization | `native` | [https://sourceforge.net/projects/srm/](https://sourceforge.net/projects/srm/) | MIT |
| 135 | **SoX** | `sox` | Media & Image Forensics | `native` | [https://sourceforge.net/projects/sox/](https://sourceforge.net/projects/sox/) | GPL-2.0+ / LGPL-2.1+ |
| 136 | **recoverjpeg** | `recoverjpeg` | Media & Image Forensics | `native` | [https://rfc1149.net/devel/recoverjpeg.html](https://rfc1149.net/devel/recoverjpeg.html) | GPL-2.0 |
| 137 | **StegSnow** | `stegsnow` | Media & Image Forensics | `native` | [http://www.darkside.com.au/snow/](http://www.darkside.com.au/snow/) | Apache-2.0 / Public Domain |
| 138 | **jsteg** | `jsteg` | Media & Image Forensics | `native` | [https://github.com/lukechampine/jsteg](https://github.com/lukechampine/jsteg) | MIT / Public Domain |
| 139 | **disktype** | `disktype` | Media & Image Forensics | `native` | [http://disktype.sourceforge.net/](http://disktype.sourceforge.net/) | MIT |
| 140 | **cabextract** | `cabextract` | Document & Metadata Harvesting | `native` | [https://www.cabextract.org.uk/](https://www.cabextract.org.uk/) | GPL-2.0+ |
| 141 | **capa** | `capa` | Document & Metadata Harvesting | `pipx` | [https://github.com/mandiant/capa](https://github.com/mandiant/capa) | Apache-2.0 |
| 142 | **FLOSS** | `floss` | Document & Metadata Harvesting | `pipx` | [https://github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss) | Apache-2.0 |
| 143 | **checkdmarc** | `checkdmarc` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/domainaware/checkdmarc](https://github.com/domainaware/checkdmarc) | Apache-2.0 |
| 144 | **pwnedornot** | `pwnedornot` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/thewhiteh4t/pwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) | MIT |
| 145 | **CrossLinked** | `crosslinked` | Email, Breach & Leak Intelligence | `pipx` | [https://github.com/m8sec/CrossLinked](https://github.com/m8sec/CrossLinked) | MIT |
| 146 | **tcpprep** | `tcpprep` | Network, PCAP & Wireless Forensics | `native` | [https://tcpreplay.appneta.com/](https://tcpreplay.appneta.com/) | GPL-3.0 |
| 147 | **dumpcap** | `dumpcap` | Network, PCAP & Wireless Forensics | `native` | [https://www.wireshark.org/docs/man-pages/dumpcap.html](https://www.wireshark.org/docs/man-pages/dumpcap.html) | GPL-2.0+ |
| 148 | **puredns** | `puredns` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/d3mondev/puredns](https://github.com/d3mondev/puredns) | MIT |
| 149 | **alterx** | `alterx` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/projectdiscovery/alterx](https://github.com/projectdiscovery/alterx) | MIT |
| 150 | **cero** | `cero` | Domain, DNS & Infrastructure Intelligence | `go` | [https://github.com/glebarez/cero](https://github.com/glebarez/cero) | MIT |
| 151 | **cloud_enum** | `cloud_enum` | Domain, DNS & Infrastructure Intelligence | `pipx` | [https://github.com/initstring/cloud_enum](https://github.com/initstring/cloud_enum) | MIT |

---

## 3. Disclaimers & Trademarks

* All product names, logos, brands, and registered trademarks mentioned in this documentation and catalog are the property of their respective owners.
* Mention of third-party tools within TraceForge does not imply endorsement, affiliation, or sponsorship by their respective developers.
* Users of TraceForge are responsible for complying with the individual license terms, acceptable use policies, and local laws governing each external utility they choose to install and execute.
