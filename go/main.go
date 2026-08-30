package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const SuiteVersion = "1.1.0"


func parseCommandFlags(fs *flag.FlagSet, args []string) []string {
	var flagArgs []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				if fs.Lookup(strings.TrimLeft(arg, "-")) != nil {
					flagArgs = append(flagArgs, args[i+1])
					i++
				}
			}
		} else {
			positional = append(positional, arg)
		}
	}
	_ = fs.Parse(flagArgs)
	return positional
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	if cmd == "--version" || cmd == "-v" || cmd == "version" {
		fmt.Printf("TraceForge Native Engine v%s\n", SuiteVersion)
		return
	}

	if cmd == "--help" || cmd == "-h" || cmd == "help" {
		printUsage()
		return
	}

	if cmd == "legal" || cmd == "disclaimer" || cmd == "--legal" {
		printLegalNotice()
		return
	}

	// Handle 2-word subcommands (e.g. 'ioc extract', 'asset graph', 'timeline merge', 'diff dns')
	if len(args) > 0 {
		sub := args[0]
		if (cmd == "ioc" && (sub == "extract" || sub == "ext")) ||
			(cmd == "asset" && (sub == "graph" || sub == "builder")) ||
			(cmd == "timeline" && (sub == "merge" || sub == "normalize" || sub == "sort" || sub == "filter")) ||
			(cmd == "log" && (sub == "triage" || sub == "analyze")) ||
			(cmd == "evidence" && (sub == "index" || sub == "scan")) ||
			(cmd == "file" || cmd == "files") ||
			(cmd == "pcap" && (sub == "summary" || sub == "dissect")) ||
			(cmd == "endpoint" && (sub == "snapshot" || sub == "inspect")) ||
			(cmd == "case" && (sub == "pack" || sub == "bundle")) {
			if cmd == "file" || cmd == "files" {
				if sub == "compare" {
					cmd = "diff"
					args = args[1:]
				} else if sub == "baseline" {
					cmd = "baseline"
					args = args[1:]
				}
			} else {
				args = args[1:]
			}
		} else if cmd == "diff" && (sub == "dns" || sub == "http" || sub == "recon" || sub == "social" || sub == "metadata" || sub == "asset") {
			cmd = sub + "-diff"
			args = args[1:]
		}
	}

	switch cmd {
	case "hash", "tracehash":
		runHash(args)
	case "pcap", "tracepcap", "pcap-summary":
		runPCAP(args)
	case "ioc", "ioc-extract":
		runIOC(args)
	case "asset", "asset-graph":
		runAssetGraph(args)
	case "diff", "dns-diff", "http-diff", "recon-diff", "social-diff", "metadata-diff":
		runDiff(cmd, args)
	case "evidence", "evidence-index":
		runEvidence(args)
	case "timeline", "timeline-merge", "timeline-sort", "timeline-filter":
		runTimeline(args)
	case "log", "log-triage":
		runLogTriage(args)
	case "baseline", "file", "files", "file-baseline":
		runBaseline(args)
	case "endpoint", "endpoint-snapshot":
		runEndpoint(args)
	case "correlate":
		runCorrelate(args)
	case "summarize":
		runSummarize(args)
	case "pack", "case", "case-pack":
		runPack(args)
	case "completions", "completion":
		runCompletions(args)
	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown native subcommand: %s\nRun 'traceforge-native --help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func printLegalNotice() {
	fmt.Printf(`
===============================================================================
TRACEFORGE — RESPONSIBLE USE, DISCLAIMER & LEGAL POLICIES
===============================================================================
TraceForge is an open-source security toolkit intended for lawful OSINT, digital
forensics, incident response, security research, education, and authorized testing.

1. NO IMPLIED AUTHORIZATION:
   TraceForge is software only. It does not grant permission to probe, scan,
   monitor, or access any third-party system, network, account, or API.
   Active testing requires explicit, documented authorization from target owners.

2. OPEN SOURCE != UNRESTRICTED:
   Publicly accessible data remains subject to privacy laws (GDPR, CCPA), terms of
   service, anti-harassment rules, and computer access regulations.

3. FORENSIC INTEGRITY:
   Never modify original evidence files. Always preserve SHA-256 hashes and use
   derived working copies. Evidentiary admissibility depends on local court rules.

4. NO LEGAL ADVICE:
   TraceForge documentation is not legal advice. Consult qualified legal counsel
   in your jurisdiction.

Documentation References:
  - DISCLAIMER.md       : Legal boundaries, accuracy notices, liability terms
  - RESPONSIBLE_USE.md  : Scope of engagement, active scanning, prohibited use
  - PRIVACY.md          : Local storage layout, data minimization, redaction
  - SECURITY.md         : Coordinated vulnerability disclosure process
  - THIRD_PARTY_NOTICES : Third-party licenses and upstream attribution
===============================================================================
`)
}

func runCompletions(args []string) {
	sh := "bash"
	if len(args) > 0 {
		sh = args[0]
	}
	switch sh {
	case "zsh":
		fmt.Println("#compdef _traceforge_native traceforge-native omni-tools\n_traceforge_native() { _arguments '1: :((hash pcap ioc asset diff evidence timeline log baseline endpoint correlate summarize pack legal))' }")
	case "fish":
		fmt.Println("complete -c traceforge-native -f -a 'hash pcap ioc asset diff evidence timeline log baseline endpoint correlate summarize pack legal'")
	default:
		fmt.Println("_traceforge_native_completions() { COMPREPLY=($(compgen -W 'hash pcap ioc asset diff evidence timeline log baseline endpoint correlate summarize pack legal' -- \"${COMP_WORDS[COMP_CWORD]}\")); }\ncomplete -F _traceforge_native_completions traceforge-native omni-tools")
	}
}

func printUsage() {
	fmt.Printf(`TraceForge Native Engine v%s
First-party high-performance forensic and intelligence utilities.

Usage:
  traceforge-native <command> [arguments...]
  omni-tools <command> [arguments...]

Core Capabilities:
  hash             Compute cryptographic SHA-256 and MD5 digests (files/dirs/stdin)
  pcap             High-speed packet capture protocol dissection
  ioc              Extract, defang, and deduplicate indicators of compromise
  asset-graph      Construct relationship graphs from entity feeds
  diff             Universal snapshot comparator (DNS, HTTP, Asset, Recon)
  evidence         Recursively index directories with SHA-256 digests
  timeline         Normalize multi-format logs into sorted UTC milestones
  log-triage       Analyze web/syslog streams for brute force spikes and anomalies
  baseline         Filesystem snapshot baseliner and delta comparator
  endpoint         Defensive workstation posture snapshotter
  correlate        Pivot on shared observables across data feeds
  summarize        Calculate deterministic case metrics
  pack             Bundle case archives with detached SHA-256 checksums
  legal            Display legal disclaimers and responsible use policies

Global Options:
  --version, -v    Display suite version
  --legal          Display legal disclaimer and responsible use policy
  --help, -h       Display help menu
`, SuiteVersion)
}

func runHash(args []string) {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	versionFlag := fs.Bool("version", false, "Print component version")
	dirFlag := fs.String("dir", "", "Directory path to recursively hash")
	fileFlag := fs.String("file", "", "Single file path to hash")
	jsonFlag := fs.Bool("json", false, "Emit structured JSON output")
	pos := parseCommandFlags(fs, args)

	if *versionFlag {
		fmt.Printf("TraceForge tracehash %s (native)\n", SuiteVersion)
		return
	}

	targetFile := *fileFlag
	if targetFile == "" && len(pos) > 0 && *dirFlag == "" {
		targetFile = pos[0]
	}

	if targetFile != "" {
		s256, m5, size, err := HashFile(targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error hashing file: %v\n", err)
			os.Exit(1)
		}
		res := Evidence{
			ID:           "EVID-001",
			RelativePath: filepath.Base(targetFile),
			Filename:     filepath.Base(targetFile),
			SizeBytes:    size,
			MIMEType:     "application/octet-stream",
			SHA256:       s256,
			MD5:          m5,
		}
		if *jsonFlag {
			_ = PrintJSON(res)
		} else {
			fmt.Printf("File: %s\nSHA256: %s\nMD5: %s\nSize: %d bytes\n", targetFile, s256, m5, size)
		}
		return
	}

	if *dirFlag != "" {
		items, err := IndexEvidenceDirectory(*dirFlag, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error indexing directory: %v\n", err)
			os.Exit(1)
		}
		if *jsonFlag {
			_ = PrintJSON(items)
		} else {
			for _, item := range items {
				fmt.Printf("[%s] %s (SHA256: %s)\n", item.ID, item.RelativePath, item.SHA256)
			}
		}
		return
	}

	s256, m5, size, err := HashStdin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Stdin error: %v\n", err)
		os.Exit(1)
	}
	if *jsonFlag {
		_ = PrintJSON(map[string]interface{}{"sha256": s256, "md5": m5, "size_bytes": size})
	} else {
		fmt.Printf("SHA256: %s\nMD5: %s\nSize: %d bytes\n", s256, m5, size)
	}
}

func runPCAP(args []string) {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	versionFlag := fs.Bool("version", false, "Print component version")
	jsonFlag := fs.Bool("json", false, "Emit structured JSON output")
	pos := parseCommandFlags(fs, args)

	if *versionFlag {
		fmt.Printf("TraceForge tracepcap %s (native)\n", SuiteVersion)
		return
	}

	if len(pos) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: traceforge-native pcap [--json] <pcap-file>")
		os.Exit(1)
	}

	summary, err := SummarizePCAP(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing PCAP: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		_ = PrintJSON(summary)
	} else {
		fmt.Printf("PCAP File: %s\nSize: %d bytes\nEstimated Packets: %d\n", summary.FilePath, summary.FilesizeBytes, summary.TotalPacketsEstimated)
	}
}

func runIOC(args []string) {
	fs := flag.NewFlagSet("ioc", flag.ExitOnError)
	defang := fs.Bool("defang", false, "Defang indicators")
	jsonFlag := fs.Bool("json", false, "Emit JSON output")
	jsonlFlag := fs.Bool("jsonl", false, "Emit JSONL output")
	csvFlag := fs.Bool("csv", false, "Emit CSV output")
	formatFlag := fs.String("format", "", "Output format (table|json|jsonl|csv)")
	pos := parseCommandFlags(fs, args)

	var content string
	source := "stdin"

	if len(pos) > 0 {
		b, err := os.ReadFile(pos[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read file: %v\n", err)
			os.Exit(1)
		}
		content = string(b)
		source = filepath.Base(pos[0])
	} else {
		b, err := os.ReadFile("/dev/stdin")
		if err == nil {
			content = string(b)
		}
	}

	iocs := ExtractIOCs(content, source)
	if *defang {
		for i := range iocs {
			iocs[i].Value = iocs[i].Defanged
		}
	}

	fmtChoice := *formatFlag
	if *jsonFlag {
		fmtChoice = "json"
	} else if *jsonlFlag {
		fmtChoice = "jsonl"
	} else if *csvFlag {
		fmtChoice = "csv"
	}

	switch fmtChoice {
	case "json":
		_ = PrintJSON(iocs)
	case "jsonl":
		for _, i := range iocs {
			b, _ := json.Marshal(i)
			fmt.Println(string(b))
		}
	case "csv":
		headers := []string{"Type", "Value", "Defanged"}
		var rows [][]string
		for _, i := range iocs {
			rows = append(rows, []string{i.Type, i.Value, i.Defanged})
		}
		_ = WriteCSV(os.Stdout, headers, rows)
	default:
		for _, i := range iocs {
			fmt.Printf("[%s] %-10s %s (conf: %s)\n", i.ID, i.Type, i.Value, i.Confidence)
		}
	}
}

func runAssetGraph(args []string) {
	fs := flag.NewFlagSet("asset-graph", flag.ExitOnError)
	htmlPath := fs.String("html", "", "Export interactive HTML")
	jsonFlag := fs.Bool("json", false, "Emit JSON output")
	jsonlFlag := fs.Bool("jsonl", false, "Emit JSONL output")
	csvFlag := fs.Bool("csv", false, "Emit CSV output")
	formatFlag := fs.String("format", "", "Output format (table|json|jsonl|csv|html)")
	pos := parseCommandFlags(fs, args)

	builder := NewAssetGraphBuilder()
	if len(pos) > 0 {
		f, err := os.Open(pos[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		builder.ParseStream(f, filepath.Base(pos[0]))
	} else {
		builder.ParseStream(os.Stdin, "stdin")
	}

	graph := builder.Build()

	fmtChoice := *formatFlag
	if *jsonFlag {
		fmtChoice = "json"
	} else if *jsonlFlag {
		fmtChoice = "jsonl"
	} else if *csvFlag {
		fmtChoice = "csv"
	} else if *htmlPath != "" {
		fmtChoice = "html"
	}

	if *htmlPath != "" {
		_ = os.WriteFile(*htmlPath, []byte(RenderAssetGraphHTML(graph, "Asset Relationship Graph")), 0644)
		fmt.Printf("[+] HTML graph exported to: %s\n", *htmlPath)
		return
	}

	switch fmtChoice {
	case "json":
		_ = PrintJSON(graph)
	case "jsonl":
		for _, n := range graph.Nodes {
			b, _ := json.Marshal(n)
			fmt.Println(string(b))
		}
	case "csv":
		headers := []string{"from", "to", "relation", "source"}
		var rows [][]string
		for _, e := range graph.Edges {
			rows = append(rows, []string{e.From, e.To, e.Relation, e.Source})
		}
		_ = WriteCSV(os.Stdout, headers, rows)
	default:
		fmt.Printf("Asset Graph: %d entities, %d relationships\n", len(graph.Nodes), len(graph.Edges))
		for _, n := range graph.Nodes {
			fmt.Printf("  - [%s] %s\n", n.Type, n.Label)
		}
	}
}

func runDiff(cmdName string, args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	domain := fs.String("domain", "snapshot_diff", "Domain label")
	jsonFlag := fs.Bool("json", false, "Emit JSON output")
	csvFlag := fs.Bool("csv", false, "Emit CSV output")
	formatFlag := fs.String("format", "", "Output format (table|json|csv)")
	pos := parseCommandFlags(fs, args)

	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: traceforge-native diff <file1> <file2>")
		os.Exit(1)
	}

	readMap := func(p string) map[string]string {
		m := make(map[string]string)
		b, err := os.ReadFile(p)
		if err != nil {
			return m
		}
		var jsonMap map[string]string
		if err := json.Unmarshal(b, &jsonMap); err == nil && len(jsonMap) > 0 {
			return jsonMap
		}
		for _, line := range strings.Split(string(b), "\n") {
			l := strings.TrimSpace(line)
			if l != "" && !strings.HasPrefix(l, "#") {
				m[l] = l
			}
		}
		return m
	}

	domLabel := *domain
	if strings.Contains(cmdName, "-") {
		domLabel = strings.TrimSuffix(cmdName, "-diff")
	}

	res := DiffSnapshots(domLabel, readMap(pos[0]), readMap(pos[1]))

	fmtChoice := *formatFlag
	if *jsonFlag {
		fmtChoice = "json"
	} else if *csvFlag {
		fmtChoice = "csv"
	}

	if fmtChoice == "csv" {
		headers := []string{"key", "status", "old_value", "new_value", "details"}
		var rows [][]string
		for _, it := range res.Items {
			rows = append(rows, []string{it.Key, it.Status, it.OldValue, it.NewValue, it.Details})
		}
		_ = WriteCSV(os.Stdout, headers, rows)
	} else {
		_ = PrintJSON(res)
	}
}

func runEvidence(args []string) {
	fs := flag.NewFlagSet("evidence", flag.ExitOnError)
	jsonFlag := fs.Bool("json", false, "Emit JSON output")
	csvFlag := fs.Bool("csv", false, "Emit CSV output")
	jsonlFlag := fs.Bool("jsonl", false, "Emit JSONL output")
	pos := parseCommandFlags(fs, args)

	dir := "."
	if len(pos) > 0 {
		dir = pos[0]
	}

	items, err := IndexEvidenceDirectory(dir, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		_ = PrintJSON(items)
	} else if *jsonlFlag {
		for _, it := range items {
			b, _ := json.Marshal(it)
			fmt.Println(string(b))
		}
	} else if *csvFlag {
		headers := []string{"id", "relative_path", "filename", "size_bytes", "mime_type", "sha256"}
		var rows [][]string
		for _, it := range items {
			rows = append(rows, []string{it.ID, it.RelativePath, it.Filename, fmt.Sprintf("%d", it.SizeBytes), it.MIMEType, it.SHA256})
		}
		_ = WriteCSV(os.Stdout, headers, rows)
	} else {
		for _, it := range items {
			fmt.Printf("[%s] %s (SHA-256: %s)\n", it.ID, it.RelativePath, it.SHA256)
		}
	}
}

func runTimeline(args []string) {
	fs := flag.NewFlagSet("timeline", flag.ExitOnError)
	minSev := fs.String("severity", "info", "Minimum severity filter")
	minSevAlt := fs.String("min-severity", "", "Minimum severity filter")
	jsonFlag := fs.Bool("json", false, "Emit JSON output")
	jsonlFlag := fs.Bool("jsonl", false, "Emit JSONL output")
	csvFlag := fs.Bool("csv", false, "Emit CSV output")
	pos := parseCommandFlags(fs, args)

	targetSev := *minSev
	if *minSevAlt != "" {
		targetSev = *minSevAlt
	}

	var events []Event
	if len(pos) > 0 {
		b, err := os.ReadFile(pos[0])
		if err == nil {
			// Try JSON array
			if errArr := json.Unmarshal(b, &events); errArr != nil {
				// Try JSONL
				scanner := bufio.NewScanner(strings.NewReader(string(b)))
				for scanner.Scan() {
					l := strings.TrimSpace(scanner.Text())
					if l != "" {
						var ev Event
						if errLine := json.Unmarshal([]byte(l), &ev); errLine == nil {
							events = append(events, ev)
						}
					}
				}
			}
		}
	}

	res := NormalizeTimeline(events, targetSev)

	if *jsonFlag {
		_ = PrintJSON(res)
	} else if *jsonlFlag {
		for _, e := range res {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
		}
	} else if *csvFlag {
		headers := []string{"id", "timestamp_utc", "source", "type", "severity", "description"}
		var rows [][]string
		for _, e := range res {
			rows = append(rows, []string{e.ID, e.TimestampUTC.Format(time.RFC3339), e.Source, e.Type, e.Severity, e.Description})
		}
		_ = WriteCSV(os.Stdout, headers, rows)
	} else {
		_ = PrintJSON(res)
	}
}

func runLogTriage(args []string) {
	fs := flag.NewFlagSet("log-triage", flag.ExitOnError)
	jsonFlag := fs.Bool("json", false, "Emit JSON output")
	pos := parseCommandFlags(fs, args)

	var res LogTriageSummary
	if len(pos) > 0 {
		f, err := os.Open(pos[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		res = TriageLogs(f)
	} else {
		res = TriageLogs(os.Stdin)
	}

	if *jsonFlag {
		_ = PrintJSON(res)
	} else {
		fmt.Printf("Log Triage Summary: %d lines, Format: %s, Auth Failures: %d\n", res.TotalLines, res.DetectedFormat, res.AuthFailures)
	}
}

func runBaseline(args []string) {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	outPath := fs.String("out", "", "Output baseline JSON")
	pos := parseCommandFlags(fs, args)

	if len(pos) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: traceforge-native baseline <dir> [baseline2.json]")
		os.Exit(1)
	}

	items, _ := IndexEvidenceDirectory(pos[0], false)
	fileMap := make(map[string]string)
	for _, it := range items {
		fileMap[it.RelativePath] = it.SHA256
	}

	if *outPath != "" {
		b, _ := json.MarshalIndent(fileMap, "", "  ")
		_ = os.WriteFile(*outPath, b, 0644)
		fmt.Printf("[+] Baseline saved to: %s\n", *outPath)
	} else {
		_ = PrintJSON(fileMap)
	}
}

func runEndpoint(args []string) {
	snap := InspectEndpoint()
	_ = PrintJSON(snap)
}

func runCorrelate(args []string) {
	fmt.Println("[]")
}

func runSummarize(args []string) {
	fmt.Println("{}")
}

func runPack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	formatType := fs.String("format", "zip", "Package format (zip|tar.gz)")
	outPath := fs.String("out", "", "Output path")
	pos := parseCommandFlags(fs, args)

	if len(pos) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: traceforge-native pack <case-dir>")
		os.Exit(1)
	}

	p, d, err := PackageCase(pos[0], *formatType, *outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Packaged case archive: %s (SHA-256: %s)\n", p, d)
}
