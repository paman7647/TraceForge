# TraceForge Tool Catalog

The suite contains **152 thoroughly audited, unique tool records** across 8 investigation domains.
Every entry is grounded in real upstream projects with verified package mappings and operational constraints.

## Media & Image Forensics

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 1 | [ExifTool](https://github.com/exiftool/exiftool) | `exiftool` | Metadata Analysis | `native` | `exiftool` | `libimage-exiftool-perl` | Reads, writes, and manipulates EXIF, IPTC, XMP, GPS, and maker notes in images, video, and documents. |
| 2 | [Binwalk](https://github.com/ReFirmLabs/binwalk) | `binwalk` | Firmware & File Carving | `native` | `binwalk` | `binwalk` | Fast signature scanner for searching binary images for embedded files and executable code. |
| 3 | [xxd](https://github.com/vim/vim) | `xxd` | Hex & Magic Bytes | `native` | `xxd` | `xxd` | Creates hex dumps of binary files and performs reversible binary/hex patching. |
| 4 | [zsteg](https://github.com/zed-0xff/zsteg) | `zsteg` | Steganography | `ruby_gem` | `zsteg` | `zsteg` | Detects hidden data and steganographic payloads in PNG and BMP bitmap channels. |
| 5 | [Steghide](https://github.com/StefanoDeVuono/steghide) | `steghide` | Steganography | `native` | `steghide` | `steghide` | Hides or extracts confidential data within JPEG, BMP, WAV, and AU files using encryption. |
| 6 | [Stegseek](https://github.com/RickdeJager/stegseek) | `stegseek` | Steganography | `native` | `stegseek` | `stegseek` | Lightning-fast cracker for steghide passphrases and hidden carrier extraction. |
| 7 | [jhead](https://github.com/Matthias-Wandel/jhead) | `jhead` | Metadata Analysis | `native` | `jhead` | `jhead` | Extracts camera settings, timestamps, and thumbnail metadata specifically from JPEG EXIF headers. |
| 8 | [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html) | `pngcheck` | Integrity & Chunk Triage | `native` | `pngcheck` | `pngcheck` | Verifies integrity of PNG, JNG, and MNG files, checking chunk CRCs and anomalies. |
| 9 | [jpeginfo](https://github.com/tjko/jpeginfo) | `jpeginfo` | Integrity & Chunk Triage | `native` | `jpeginfo` | `jpeginfo` | Generates diagnostic reports and structural integrity checks for JPEG and JFIF files. |
| 10 | [ImageMagick](https://github.com/ImageMagick/ImageMagick) | `magick` | Image Processing | `native` | `imagemagick` | `imagemagick` | Image manipulation, format conversion, and pixel analysis toolset. |
| 11 | [GraphicsMagick](http://www.graphicsmagick.org/) | `gm` | Image Processing | `native` | `graphicsmagick` | `graphicsmagick` | High-performance Swiss army knife of image processing and structural comparison. |
| 12 | [Exiv2](https://github.com/Exiv2/exiv2) | `exiv2` | Metadata Analysis | `native` | `exiv2` | `exiv2` | C++ library and command-line utility to manage image metadata (Exif, IPTC, XMP, ICC profiles). |
| 13 | [FFmpeg](https://github.com/FFmpeg/FFmpeg) | `ffmpeg` | Audio & Video Forensics | `native` | `ffmpeg` | `ffmpeg` | Universal multimedia processing framework for video decoding, frame extraction, and filtering. |
| 14 | [FFprobe](https://github.com/FFmpeg/FFmpeg) | `ffprobe` | Audio & Video Forensics | `native` | `ffmpeg` | `ffmpeg` | Multimedia stream analyzer that outputs detailed codec, stream, and container metadata in JSON. |
| 15 | [Foremost](https://github.com/korczis/foremost) | `foremost` | Carving & Recovery | `native` | `foremost` | `foremost` | Forensic data carving program based on headers, footers, and internal data structures. |
| 16 | [Scalpel](https://github.com/sleuthkit/scalpel) | `scalpel` | Carving & Recovery | `native` | `scalpel` | `scalpel` | Frugal, high-performance file carver reading configuration-based file header/footer rules. |
| 17 | [bulk_extractor](https://github.com/simsong/bulk_extractor) | `bulk_extractor` | Feature Extraction | `native` | `bulk-extractor` | `bulk-extractor` | High-speed feature extractor scanning disk images or files without parsing filesystem structures. |
| 18 | [PhotoRec](https://github.com/cgsecurity/testdisk) | `photorec` | Carving & Recovery | `native` | `testdisk` | `testdisk` | Signature-based file recovery utility capable of carving 480+ file formats from raw storage. |
| 19 | [TestDisk](https://github.com/cgsecurity/testdisk) | `testdisk` | Filesystem Forensics | `native` | `testdisk` | `testdisk` | Checks and undeletes partitions, fixes partition tables, and recovers lost boot sectors. |
| 20 | [YARA](https://github.com/VirusTotal/yara) | `yara` | Pattern & Signature Matching | `native` | `yara` | `yara` | Pattern matching Swiss army knife for identifying and classifying malware samples and artifacts. |
| 21 | [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) | `tesseract` | OCR & Text Extraction | `native` | `tesseract` | `tesseract-ocr` | Open-source optical character recognition engine with support for over 100 languages. |
| 22 | [GPSBabel](https://github.com/gpsbabel/gpsbabel) | `gpsbabel` | GEOINT & Navigation | `native` | `gpsbabel` | `gpsbabel` | Converts waypoints, tracks, and routes between popular GPS data formats (GPX, KML, NMEA). |
| 23 | [GDAL Info](https://github.com/OSGeo/gdal) | `gdalinfo` | GEOINT & Geospatial | `native` | `gdal` | `gdal-bin` | Lists information about raster geospatial datasets, projections, and ground control points. |
| 24 | [MediaInfo](https://github.com/MediaArea/MediaInfo) | `mediainfo` | Audio & Video Forensics | `native` | `mediainfo` | `mediainfo` | Displays technical and tag information about video and audio files across hundreds of formats. |
| 25 | [yt-dlp](https://github.com/yt-dlp/yt-dlp) | `yt-dlp` | Media Acquisition | `pipx` | `yt-dlp` | `yt-dlp` | Command-line media downloader supporting thousands of video and streaming websites. |
| 26 | [gallery-dl](https://github.com/mikf/gallery-dl) | `gallery-dl` | Media Acquisition | `pipx` | `gallery-dl` | `gallery-dl` | Image gallery downloader for public image hosting services, social platforms, and forums. |
| 27 | [OCRmyPDF](https://github.com/ocrmypdf/OCRmyPDF) | `ocrmypdf` | OCR & Text Extraction | `pipx` | `ocrmypdf` | `ocrmypdf` | Adds an OCR text layer to scanned PDF files, enabling full-text search while preserving images. |
| 28 | [ZBar](https://github.com/mchehab/zbar) | `zbarimg` | Barcode & QR Forensics | `native` | `zbar` | `zbar-tools` | Scans and decodes QR codes, EAN, UPC, Code 128, and other 1D/2D barcodes from images. |
| 29 | [Hachoir Metadata](https://github.com/vstinner/hachoir) | `hachoir-metadata` | Metadata Analysis | `pipx` | `hachoir` | `hachoir` | Extracts metadata from multimedia, archive, document, and binary executable formats. |
| 30 | [WebP Tools](https://chromium.googlesource.com/webm/libwebp) | `cwebp` | Format Conversion | `native` | `webp` | `webp` | Encodes and decodes WebP image assets and displays compression profile metadata. |
| 31 | [AVIF Tools](https://github.com/AOMediaCodec/libavif) | `avifdec` | Format Conversion | `native` | `libavif` | `libavif-bin` | Decodes AVIF image formats into PNG/JPEG for downstream forensic processing. |
| 32 | [HEIF Tools](https://github.com/strukturag/libheif) | `heif-convert` | Format Conversion | `native` | `libheif` | `libheif-examples` | Converts Apple/ISO HEIC and HEIF photos to PNG/JPEG preserving EXIF and depth layers. |
| 33 | [Osmium Tool](https://github.com/osmcode/osmium-tool) | `osmium` | GEOINT & Geospatial | `native` | `osmium-tool` | `osmium-tool` | Fast processing of OpenStreetMap data in PBF, XML, and OSM formats. |
| 34 | [OutGuess](https://github.com/resurrecting-open-source-projects/outguess) | `outguess` | Steganography | `native` | `outguess` | `outguess` | Universal steganographic tool that allows the insertion of hidden data into redundant bits of data sources. |
| 135 | [SoX](https://sourceforge.net/projects/sox/) | `sox` | Audio & Spectrogram Analysis | `native` | `sox` | `sox` | Swiss Army knife of sound processing, converting formats and generating audio spectrograms for audio stego. |
| 136 | [recoverjpeg](https://rfc1149.net/devel/recoverjpeg.html) | `recoverjpeg` | File Carving | `native` | `recoverjpeg` | `recoverjpeg` | Recovers JFIF (JPEG) pictures and MOV/AVI movies from raw disk images and unallocated blocks. |
| 137 | [StegSnow](http://www.darkside.com.au/snow/) | `stegsnow` | Whitespace Steganography | `native` | `stegsnow` | `stegsnow` | Conceals and extracts arbitrary payload messages in ASCII text by appending spaces and tabs at line ends. |
| 138 | [jsteg](https://github.com/lukechampine/jsteg) | `jsteg` | JPEG Steganography | `native` | `jsteg` | `jsteg` | Hides and reveals hidden data inside 1-bit DCT coefficients of standard JPEG images. |
| 139 | [disktype](http://disktype.sourceforge.net/) | `disktype` | Disk & Partition Triage | `native` | `disktype` | `disktype` | Detects the format of a disk or disk image, identifying partition tables, filesystems, and bootloaders. |

## Identity, Social & SOCMINT

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 35 | [Sherlock](https://github.com/sherlock-project/sherlock) | `sherlock` | Username Search | `pipx` | `sherlock-project` | `sherlock-project` | Hunts down social media accounts by username across hundreds of public online services. |
| 36 | [Maigret](https://github.com/soxoj/maigret) | `maigret` | Username Dossier | `pipx` | `maigret` | `maigret` | Collects a detailed dossier on a person by username across 3,000+ public websites and platforms. |
| 37 | [Blackbird](https://github.com/p1ngul1n0/blackbird) | `blackbird` | Username Search | `pipx` | `blackbird-osint` | `blackbird-osint` | Fast OSINT tool to search for accounts by username across 500+ websites. |
| 38 | [Socialscan](https://github.com/iojw/socialscan) | `socialscan` | Username & Email Check | `pipx` | `socialscan` | `socialscan` | Offers accurate username and email address availability checking without rate-limit issues. |
| 39 | [sn0int](https://github.com/kpcyrd/sn0int) | `sn0int` | Reconnaissance Framework | `cargo` | `sn0int` | `sn0int` | Semi-automatic OSINT framework and package manager designed to harvest intelligence and graph relations. |
| 40 | [Recon-ng](https://github.com/lanmaster53/recon-ng) | `recon-ng` | Reconnaissance Framework | `native` | `recon-ng` | `recon-ng` | Full-featured modular Web Reconnaissance framework with interactive console and database backend. |
| 41 | [SpiderFoot](https://github.com/smicallef/spiderfoot) | `spiderfoot` | OSINT Automation | `pipx` | `spiderfoot` | `spiderfoot` | Automated OSINT collection engine integrating 200+ modules for domains, IPs, emails, and names. |
| 42 | [Twarc](https://github.com/DocNow/twarc) | `twarc2` | Social Data Archival | `pipx` | `twarc` | `twarc` | Command line tool and Python library for archiving Twitter/X JSON data. |
| 43 | [Snscrape](https://github.com/JustAnotherArchivist/snscrape) | `snscrape` | Social Data Scraping | `pipx` | `snscrape` | `snscrape` | Scraper for social networking services such as Twitter, Facebook, Instagram, Reddit, and VKontakte. |
| 44 | [Snoop](https://github.com/snooppr/snoop) | `snoop` | Username Search | `manual` | `manual` | `manual` | Searches for public user accounts across thousands of Russian, CIS, and global internet services. |
| 45 | [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | `whatsmyname` | Username Database | `manual` | `manual` | `manual` | Central community-curated JSON database and detection rules for username enumeration. |
| 46 | [DiscordChatExporter](https://github.com/Tyrrrz/DiscordChatExporter) | `DiscordChatExporter-CLI` | Channel Archival | `manual` | `manual` | `manual` | Exports chat logs from authorized Discord channels to HTML, JSON, CSV, or plain text. |

## Email, Breach & Leak Intelligence

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 47 | [Holehe](https://github.com/megadose/holehe) | `holehe` | Account Discovery | `pipx` | `holehe` | `holehe` | Checks if an email is attached to an account on 120+ public websites without sending notifications. |
| 48 | [h8mail](https://github.com/khast3x/h8mail) | `h8mail` | Breach Intelligence | `pipx` | `h8mail` | `h8mail` | Email breach intelligence and password hunting tool using local breach dumps and public search APIs. |
| 49 | [theHarvester](https://github.com/laramies/theHarvester) | `theHarvester` | Public OSINT Aggregation | `pipx` | `theHarvester` | `theHarvester` | Gathers emails, names, subdomains, IPs, and URLs using search engines, PGP key servers, and passive APIs. |
| 50 | [GHunt](https://github.com/mxrch/GHunt) | `ghunt` | Google Account OSINT | `pipx` | `ghunt` | `ghunt` | Modular offensive and defensive OSINT tool to extract information from Google accounts and emails. |
| 51 | [EmailRep](https://github.com/sublime-security/emailrep.io-python) | `emailrep` | Email Reputation | `pipx` | `emailrep` | `emailrep` | Scores email addresses against reputation indicators, deliverability signals, and breach records. |
| 52 | [Gitleaks](https://github.com/gitleaks/gitleaks) | `gitleaks` | Secret & Credential Scanning | `native` | `gitleaks` | `gitleaks` | High-performance SAST tool for detecting hardcoded secrets like passwords, API keys, and tokens in git repos. |
| 53 | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | `trufflehog` | Secret & Credential Scanning | `native` | `trufflehog` | `trufflehog` | Finds credentials and secrets across git repositories, filesystems, and S3 buckets with verification. |
| 54 | [GitGuardian Shield](https://github.com/GitGuardian/ggshield) | `ggshield` | Secret & Credential Scanning | `pipx` | `ggshield` | `ggshield` | CLI application to scan files, repositories, and CI environments for 400+ types of secrets and credentials. |
| 55 | [CeWL](https://github.com/digininja/CeWL) | `cewl` | Custom Wordlist Generator | `ruby_gem` | `cewl` | `cewl` | Custom wordlist generator spidering websites to a specified depth to extract industry-specific vocabulary. |
| 56 | [John the Ripper](https://github.com/openwall/john) | `john` | Hash Analysis & Audit | `native` | `john` | `john` | Fast password hash auditing tool and recovery engine supporting hundreds of hash and cipher types. |
| 57 | [Hashcat](https://github.com/hashcat/hashcat) | `hashcat` | Hash Analysis & Audit | `native` | `hashcat` | `hashcat` | World's fastest and most advanced password recovery and hash auditing utility. |
| 58 | [Intelligence X CLI](https://github.com/IntelligenceX/SDK) | `intelx` | Breach & Archive Search | `pipx` | `intelx` | `intelx` | Official Python SDK and CLI tool for Intelligence X (intelx.io) search and archive engine. |
| 143 | [checkdmarc](https://github.com/domainaware/checkdmarc) | `checkdmarc` | Email Authentication Triage | `pipx` | `checkdmarc` | `checkdmarc` | Parses and validates SPF, DMARC, DKIM, MTA-STS, and BIMI DNS records for an email domain. |
| 144 | [pwnedornot](https://github.com/thewhiteh4t/pwnedOrNot) | `pwnedornot` | Breach Exposure Lookup | `pipx` | `pwnedornot` | `pwnedornot` | Queries HaveIBeenPwned API v3 to discover compromised passwords, paste exposures, and breach details. |
| 145 | [CrossLinked](https://github.com/m8sec/CrossLinked) | `crosslinked` | Corporate Employee OSINT | `pipx` | `crosslinked` | `crosslinked` | LinkedIn employee enumeration tool using search engine scraping to discover organizational email patterns. |

## Network, PCAP & Wireless Forensics

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 59 | [TShark](https://gitlab.com/wireshark/wireshark) | `tshark` | Packet Dissection | `native` | `tshark` | `tshark` | Terminal-oriented network protocol analyzer that parses packets live or from capture files (pcap/pcapng). |
| 60 | [Capinfos](https://gitlab.com/wireshark/wireshark) | `capinfos` | Capture File Triage | `native` | `tshark` | `tshark` | Prints statistical information about capture files (encapsulation, packet count, times). |
| 61 | [Editcap](https://gitlab.com/wireshark/wireshark) | `editcap` | Capture File Manipulation | `native` | `tshark` | `tshark` | Selects, extracts, trims, or translates packets from one capture file into another. |
| 62 | [Mergecap](https://gitlab.com/wireshark/wireshark) | `mergecap` | Capture File Manipulation | `native` | `tshark` | `tshark` | Combines multiple saved capture files into a single chronologically sorted output capture file. |
| 63 | [tcpdump](https://github.com/the-tcpdump-group/tcpdump) | `tcpdump` | Packet Capture | `native` | `tcpdump` | `tcpdump` | Command-line packet analyzer and capture utility utilizing libpcap filters. |
| 64 | [Nmap](https://github.com/nmap/nmap) | `nmap` | Network Discovery | `native` | `nmap` | `nmap` | Network exploration tool and security / port scanner with NSE scripting engine. |
| 65 | [Masscan](https://github.com/robertdavidgraham/masscan) | `masscan` | Asynchronous Port Scanner | `native` | `masscan` | `masscan` | Asynchronous TCP port scanner transmitting SYN packets at up to 10 million packets per second. |
| 66 | [RustScan](https://github.com/RustScan/RustScan) | `rustscan` | Fast Port Scanner | `cargo` | `rustscan` | `rustscan` | Fast port scanner written in Rust that quickly scans all 65,535 ports and pipes results into Nmap. |
| 67 | [Aircrack-NG](https://github.com/aircrack-ng/aircrack-ng) | `aircrack-ng` | 802.11 Wireless Forensics | `native` | `aircrack-ng` | `aircrack-ng` | Complete suite of wireless security assessment tools to capture, filter, and audit 802.11 traffic. |
| 68 | [hcxpcapngtool](https://github.com/ZerBea/hcxtools) | `hcxpcapngtool` | 802.11 Wireless Forensics | `native` | `hcxtools` | `hcxtools` | Converts PCAPNG capture files containing 802.11 frames to Hashcat (22000) and John hash formats. |
| 69 | [Zeek](https://github.com/zeek/zeek) | `zeek` | Network Security Monitoring | `native` | `zeek` | `zeek` | Open-source network security monitoring platform converting packet streams into structured connection logs. |
| 70 | [Suricata](https://github.com/OISF/suricata) | `suricata` | IDS / IPS Engine | `native` | `suricata` | `suricata` | Mature, high-performance Network Threat Detection and PCAP intrusion analysis engine. |
| 71 | [arp-scan](https://github.com/royhills/arp-scan) | `arp-scan` | Local Layer-2 Discovery | `native` | `arp-scan` | `arp-scan` | Sends ARP packets to discover and fingerprint active IPv4 hosts on local Ethernet/Wi-Fi networks. |
| 72 | [Netdiscover](https://github.com/netdiscover-scanner/netdiscover) | `netdiscover` | Local Layer-2 Discovery | `native` | `netdiscover` | `netdiscover` | Active/passive ARP reconnaissance tool for finding live hosts on wireless or switched LANs. |
| 73 | [hping3](https://github.com/antirez/hping) | `hping3` | Packet Crafting | `native` | `hping` | `hping3` | Network tool able to send custom TCP/IP packets and display target replies for firewall testing. |
| 74 | [Mitmproxy](https://github.com/mitmproxy/mitmproxy) | `mitmproxy` | HTTP/HTTPS Inspection | `pipx` | `mitmproxy` | `mitmproxy` | Interactive TLS-capable intercepting HTTP/HTTPS proxy and traffic analysis console. |
| 146 | [tcpprep](https://tcpreplay.appneta.com/) | `tcpprep` | PCAP Splitting & Preprocessing | `native` | `tcpreplay` | `tcpreplay` | Preprocesses PCAP files to separate traffic into client and server flows for deterministic replay. |
| 147 | [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) | `dumpcap` | Raw High-Speed Packet Capture | `native` | `wireshark` | `wireshark-common` | Lightweight, highly optimized raw network packet capture engine with minimal memory footprint. |

## Domain, DNS & Infrastructure Intelligence

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 75 | [Subfinder](https://github.com/projectdiscovery/subfinder) | `subfinder` | Subdomain Discovery | `go` | `subfinder` | `github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Fast passive subdomain enumeration tool that discovers valid subdomains using passive online sources. |
| 76 | [Amass](https://github.com/owasp-amass/amass) | `amass` | Network Mapping & Attack Surface | `go` | `amass` | `github.com/owasp-amass/amass/v4/...@latest` | In-depth attack surface mapping and external asset discovery framework using open-source intelligence. |
| 77 | [Assetfinder](https://github.com/tomnomnom/assetfinder) | `assetfinder` | Subdomain Discovery | `go` | `github.com/tomnomnom/assetfinder@latest` | `github.com/tomnomnom/assetfinder@latest` | Finds domains and subdomains related to a given target domain using various public feeds. |
| 78 | [dnsx](https://github.com/projectdiscovery/dnsx) | `dnsx` | DNS Resolver & Prober | `go` | `dnsx` | `github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | Fast and multi-purpose DNS toolkit allowing multiple DNS queries, resolution, and brute-forcing. |
| 79 | [httpx](https://github.com/projectdiscovery/httpx) | `httpx` | HTTP Probing & Tech Detect | `go` | `httpx` | `github.com/projectdiscovery/httpx/cmd/httpx@latest` | Fast and multi-purpose HTTP toolkit for probing web servers, status codes, titles, and technologies. |
| 80 | [Naabu](https://github.com/projectdiscovery/naabu) | `naabu` | Port Scanner | `go` | `naabu` | `github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | Fast SYN/CONNECT port scanner focused on reliability, simplicity, and integration into OSINT pipelines. |
| 81 | [Katana](https://github.com/projectdiscovery/katana) | `katana` | Web Crawling & Spidering | `go` | `katana` | `github.com/projectdiscovery/katana/cmd/katana@latest` | Web crawling and spidering framework supporting headless automation and JS parsing. |
| 82 | [Nuclei](https://github.com/projectdiscovery/nuclei) | `nuclei` | Vulnerability & Config Scanner | `go` | `nuclei` | `github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Fast and customizable vulnerability and misconfiguration scanner based on community YAML templates. |
| 83 | [Uncover](https://github.com/projectdiscovery/uncover) | `uncover` | Cyber-Search Aggregator | `go` | `uncover` | `github.com/projectdiscovery/uncover/cmd/uncover@latest` | Quickly discovers exposed hosts across Shodan, Censys, FOFA, Hunter, ZoomEye, and Criminal IP. |
| 84 | [Notify](https://github.com/projectdiscovery/notify) | `notify` | Pipeline Notification | `go` | `notify` | `github.com/projectdiscovery/notify/cmd/notify@latest` | Pipes command-line pipeline findings directly to Discord, Slack, Telegram, and webhooks. |
| 85 | [GAU](https://github.com/lc/gau) | `gau` | Historical URL Extraction | `go` | `gau` | `github.com/lc/gau/v2/cmd/gau@latest` | Fetches known URLs from AlienVault OTX, Wayback Machine, and Common Crawl for any given domain. |
| 86 | [Waybackurls](https://github.com/tomnomnom/waybackurls) | `waybackurls` | Historical URL Extraction | `go` | `github.com/tomnomnom/waybackurls@latest` | `github.com/tomnomnom/waybackurls@latest` | Fetches all URLs that the Wayback Machine has indexed for a given domain name. |
| 87 | [Gowitness](https://github.com/sensepost/gowitness) | `gowitness` | Web Screenshotting | `go` | `github.com/sensepost/gowitness@latest` | `github.com/sensepost/gowitness@latest` | Golang web screenshot utility using Chrome Headless to generate visual asset catalogs of web servers. |
| 88 | [dig](https://gitlab.isc.org/isc-projects/bind9) | `dig` | DNS Lookup | `native` | `bind` | `dnsutils` | Flexible command-line tool for interrogating DNS name servers and inspecting RR records. |
| 89 | [whois](https://github.com/rfc1036/whois) | `whois` | Registration Data | `native` | `whois` | `whois` | Client for the WHOIS protocol to retrieve domain registration, registrar, and IP block allocation data. |
| 90 | [DNSRecon](https://github.com/darkoperator/dnsrecon) | `dnsrecon` | DNS Enumeration | `pipx` | `dnsrecon` | `dnsrecon` | DNS enumeration tool performing zone transfers, reverse lookups, SRV records, and cache snooping. |
| 91 | [dnstwist](https://github.com/elceef/dnstwist) | `dnstwist` | Typosquatting & Phishing | `pipx` | `dnstwist` | `dnstwist` | Domain name permutation engine for detecting typosquatting, phishing domains, and brand impersonation. |
| 92 | [WafW00f](https://github.com/EnableSecurity/wafw00f) | `wafw00f` | WAF Fingerprinting | `pipx` | `wafw00f` | `wafw00f` | Identifies and fingerprints Web Application Firewall (WAF) products protecting a website. |
| 93 | [Prowler](https://github.com/prowler-cloud/prowler) | `prowler` | Cloud Security Assessment | `pipx` | `prowler` | `prowler` | Security tool to perform cloud security assessments, audits, and compliance checks (AWS, Azure, GCP). |
| 94 | [Shodan CLI](https://github.com/achillean/shodan-python) | `shodan` | Internet Scanner Search | `pipx` | `shodan` | `shodan` | Command-line interface to the Shodan search engine for discovering connected devices and services. |
| 95 | [Censys CLI](https://github.com/censys/censys-python) | `censys` | Internet Scanner Search | `pipx` | `censys` | `censys` | Command-line interface for the Censys search engine for querying internet-wide scan data and certificates. |
| 96 | [S3Scanner](https://github.com/sa7mon/S3Scanner) | `s3scanner` | Cloud Storage Exposure | `pipx` | `s3scanner` | `s3scanner` | Scans open Amazon S3 buckets and dumps their contents to discover exposed corporate assets. |
| 97 | [MapCIDR](https://github.com/projectdiscovery/mapcidr) | `mapcidr` | IP & Subnet Utility | `go` | `github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest` | `github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest` | Utility for subnet calculation, CIDR expansion, slicing, and IP range manipulation. |
| 98 | [ASNmap](https://github.com/projectdiscovery/asnmap) | `asnmap` | ASN & IP Intelligence | `go` | `github.com/projectdiscovery/asnmap/cmd/asnmap@latest` | `github.com/projectdiscovery/asnmap/cmd/asnmap@latest` | Gathers network ranges and CIDRs assigned to autonomous system numbers, organizations, or domains. |
| 99 | [CDNcheck](https://github.com/projectdiscovery/cdncheck) | `cdncheck` | CDN & WAF Identification | `go` | `github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` | `github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` | Identifies whether an IP address belongs to a known CDN, cloud provider, or WAF network. |
| 100 | [TLSx](https://github.com/projectdiscovery/tlsx) | `tlsx` | TLS & Certificate Recon | `go` | `github.com/projectdiscovery/tlsx/cmd/tlsx@latest` | `github.com/projectdiscovery/tlsx/cmd/tlsx@latest` | Fast and configurable TLS data grabber and certificate parser extracting SANs, issuers, and ciphers. |
| 148 | [puredns](https://github.com/d3mondev/puredns) | `puredns` | Mass DNS Resolver | `go` | `puredns` | `puredns` | Fast domain resolver and active subdomain brute-forcer that cleans wildcard DNS and validates public resolvers. |
| 149 | [alterx](https://github.com/projectdiscovery/alterx) | `alterx` | Subdomain Permutation | `go` | `alterx` | `alterx` | Fast and customizable subdomain wordlist generator using regex patterns and word permutations. |
| 150 | [cero](https://github.com/glebarez/cero) | `cero` | TLS Certificate Scraping | `go` | `cero` | `cero` | Scrapes Subject Alternative Names (SAN) and Common Names from SSL/TLS certificates across IP ranges. |
| 151 | [cloud_enum](https://github.com/initstring/cloud_enum) | `cloud_enum` | Multi-Cloud Bucket Enumerator | `pipx` | `cloud-enum` | `cloud-enum` | Multi-cloud OSINT tool that enumerates public resources in AWS (S3, Apps), Azure (Blobs, Tables), and GCP. |

## Document & Metadata Harvesting

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 101 | [pdfinfo](https://poppler.freedesktop.org/) | `pdfinfo` | PDF Metadata | `native` | `poppler` | `poppler-utils` | Prints the contents of the Info dictionary (title, author, creator, producer, dates) from a PDF file. |
| 102 | [pdftotext](https://poppler.freedesktop.org/) | `pdftotext` | Text Extraction | `native` | `poppler` | `poppler-utils` | Converts Portable Document Format (PDF) files to plain text while maintaining original layout. |
| 103 | [pdfimages](https://poppler.freedesktop.org/) | `pdfimages` | Image Extraction | `native` | `poppler` | `poppler-utils` | Extracts all embedded images from a PDF file in their native formats (JPEG, TIFF, PNG). |
| 104 | [QPDF](https://github.com/qpdf/qpdf) | `qpdf` | Structural PDF Analysis | `native` | `qpdf` | `qpdf` | Command-line tool and C++ library for content-preserving transformations on PDF files. |
| 105 | [MuPDF mutool](https://mupdf.com/) | `mutool` | PDF & XPS Triage | `native` | `mupdf-tools` | `mupdf-tools` | Command-line tool for viewing, extracting, and manipulating PDF, XPS, and EPUB files. |
| 106 | [Ripgrep](https://github.com/BurntSushi/ripgrep) | `rg` | Text & Secret Search | `native` | `ripgrep` | `ripgrep` | Extremely fast line-oriented search tool that recursively searches directories for regex patterns. |
| 107 | [fd](https://github.com/sharkdp/fd) | `fd` | Filesystem Discovery | `native` | `fd` | `fd-find` | Simple, fast and user-friendly alternative to find, respecting .gitignore automatically. |
| 108 | [jq](https://github.com/jqlang/jq) | `jq` | Structured Data Query | `native` | `jq` | `jq` | Lightweight and flexible command-line JSON processor for filtering, mapping, and transforming data. |
| 109 | [olevba](https://github.com/decalage2/oletools) | `olevba` | Macro & OLE Analysis | `pipx` | `oletools` | `oletools` | Parses OLE and OpenXML files (Word, Excel, PowerPoint) to detect, extract, and analyze VBA macros. |
| 110 | [oleid](https://github.com/decalage2/oletools) | `oleid` | Macro & OLE Analysis | `pipx` | `oletools` | `oletools` | Analyzes OLE and MS Office files to identify suspicious characteristics, encryption, and embedded objects. |
| 111 | [olemeta](https://github.com/decalage2/oletools) | `olemeta` | Macro & OLE Analysis | `pipx` | `oletools` | `oletools` | Extracts standard and custom metadata from OLE files (author, last editor, revision, edit time). |
| 112 | [docx2txt](https://docx2txt.sourceforge.net/) | `docx2txt` | Text Extraction | `native` | `docx2txt` | `docx2txt` | Command-line utility that extracts text and embedded media directly from Microsoft docx files. |
| 113 | [Antiword](http://www.winfield.demon.nl/) | `antiword` | Legacy Document Extraction | `native` | `antiword` | `antiword` | Converts legacy binary MS Word documents (.doc) to plain text and PostScript format. |
| 114 | [Catdoc](https://www.wagner.pp.ru/~vitus/software/catdoc/) | `catdoc` | Legacy Document Extraction | `native` | `catdoc` | `catdoc` | Extracts readable text from MS-Word, MS-Excel (xls2csv), and PowerPoint (catppt) presentation files. |
| 115 | [Pandoc](https://github.com/jgm/pandoc) | `pandoc` | Universal Document Converter | `native` | `pandoc` | `pandoc` | Universal markup converter translating between Markdown, HTML, PDF, docx, EPUB, and LaTeX. |
| 116 | [PeePDF](https://github.com/jesparza/peepdf) | `peepdf` | PDF Security Analysis | `manual` | `manual` | `manual` | Python tool to explore and analyze PDF files to check for suspicious elements, JavaScript, and shellcode. |
| 117 | [PDFiD](https://github.com/DidierStevens/DidierStevensSuite) | `pdfid` | PDF Security Analysis | `manual` | `manual` | `manual` | Scans a PDF file to look for suspicious elements such as /JavaScript, /Launch, /EmbeddedFile, and /OpenAction. |
| 140 | [cabextract](https://www.cabextract.org.uk/) | `cabextract` | Archive Decompression | `native` | `cabextract` | `cabextract` | Decompresses and extracts files from Microsoft cabinet (.cab) archives, self-extractors, and installer setups. |
| 141 | [capa](https://github.com/mandiant/capa) | `capa` | Executable Capability Triage | `pipx` | `flare-capa` | `flare-capa` | Identifies capabilities in executable files using the FLARE rule ecosystem to map ATT&CK tactics. |
| 142 | [FLOSS](https://github.com/mandiant/flare-floss) | `floss` | Deobfuscated String Extraction | `pipx` | `flare-floss` | `flare-floss` | FLARE Obfuscated String Solver: automatically extracts obfuscated, tight, and stack strings from binaries. |

## OPSEC & Metadata Anonymization

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 118 | [MAT2](https://0xacab.org/jvoisin/mat2) | `mat2` | Metadata Sanitization | `native` | `mat2` | `mat2` | Metadata Anonymisation Toolkit v2 supporting non-destructive cleaning across images, audio, and docs. |
| 119 | [Proxychains-NG](https://github.com/rofl0r/proxychains-ng) | `proxychains4` | Network Routing & Proxy | `native` | `proxychains-ng` | `proxychains4` | Hooks network-related dynamic calls in dynamically linked programs and routes them through SOCKS/HTTP proxies. |
| 120 | [Tor](https://gitlab.torproject.org/tpo/core/tor) | `tor` | Anonymity Network | `native` | `tor` | `tor` | The Onion Router providing censorship resistance, encrypted multi-hop routing, and onion service access. |
| 121 | [torsocks](https://gitlab.torproject.org/tpo/core/torsocks) | `torsocks` | Anonymity Network | `native` | `torsocks` | `torsocks` | Wrapper to transparently route all network traffic of a command through the Tor network safely. |
| 122 | [macchanger](https://github.com/alobbs/macchanger) | `macchanger` | Link Layer Privacy | `native` | `macchanger` | `macchanger` | Utility for viewing and manipulating the MAC address of network interfaces. |
| 123 | [WireGuard](https://git.zx2c4.com/wireguard-tools/) | `wg` | Encrypted Tunneling | `native` | `wireguard-tools` | `wireguard-tools` | Fast and secure VPN tunnel utility using ChaCha20-Poly1305 cryptography. |
| 124 | [Privoxy](https://www.privoxy.org/) | `privoxy` | Privacy Filtering Proxy | `native` | `privoxy` | `privoxy` | Non-caching web proxy with advanced filtering capabilities for enhancing privacy and modifying headers. |
| 125 | [Cloudflared](https://github.com/cloudflare/cloudflared) | `cloudflared` | DNS over HTTPS (DoH) | `native` | `cloudflared` | `cloudflared` | Cloudflare Tunnel client providing secure DNS over HTTPS (DoH) proxying to prevent local DNS inspection. |
| 126 | [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) | `dnscrypt-proxy` | Encrypted DNS Protocol | `native` | `dnscrypt-proxy` | `dnscrypt-proxy` | Flexible DNS proxy communicating with secure resolvers supporting DNSCrypt and DNS-over-HTTPS. |
| 127 | [Stubby](https://github.com/getdnsapi/stubby) | `stubby` | DNS over TLS (DoT) | `native` | `stubby` | `stubby` | Local DNS Privacy stub resolver that encrypts DNS queries using DNS-over-TLS (DoT). |
| 128 | [OpenSSH](https://www.openssh.com/) | `ssh` | Encrypted Remote Shell & Dynamic Proxy | `native` | `openssh` | `openssh-client` | Premier connectivity tool for remote login and encrypted dynamic SOCKS proxy tunneling (-D). |
| 129 | [socat](http://www.dest-unreach.org/socat/) | `socat` | Multipurpose Relay | `native` | `socat` | `socat` | Multipurpose relay tool establishing two bidirectional byte streams across sockets, pipes, and SSL. |
| 130 | [Ncat](https://nmap.org/ncat/) | `ncat` | Network Read & Write | `native` | `nmap` | `ncat` | Modern reimplementation of Netcat supporting SSL, IPv6, SOCKS4/5 proxying, and connection brokering. |
| 131 | [GnuPG](https://gnupg.org/) | `gpg` | Cryptographic Signing & Encryption | `native` | `gnupg` | `gnupg` | Complete implementation of the OpenPGP standard for signing, encrypting, and verifying sensitive evidence. |
| 132 | [age](https://github.com/FiloSottile/age) | `age` | Modern File Encryption | `native` | `age` | `age` | Simple, modern and secure file encryption tool with small explicit keys (X25519) and no config. |
| 133 | [OpenSSL](https://github.com/openssl/openssl) | `openssl` | Cryptographic Toolkit | `native` | `openssl` | `openssl` | Robust, commercial-grade cryptographic library and CLI toolkit for SSL/TLS, certificates, and ciphers. |
| 134 | [Secure Delete (srm)](https://sourceforge.net/projects/srm/) | `srm` | Secure Deletion | `native` | `srm` | `secure-delete` | Securely overwrites files and free disk space to prevent data recovery from magnetic/flash media. |

## First-Party Suite Native Tools

| ID | Name | Executable | Subcategory | Ecosystem | macOS (Brew) | Linux (APT/pipx/Go) | Description |
|---:|---|---|---|---|---|---|---|
| 152 | [TraceForge Native Tools](https://github.com/paman7647/TraceForge) | `traceforge-native` | Core Forensics & Normalization Engine | `go` | `traceforge-native` | `traceforge-native` | First-party native CLI engine for graph generation, snapshot diffing, streaming IOC extraction, log triage, timeline normalization, and case packaging. |
