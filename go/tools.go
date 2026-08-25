package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// 1. Asset Graph Engine
// -----------------------------------------------------------------------------
type AssetGraphBuilder struct {
	nodes map[string]AssetNode
	edges []AssetEdge
}

func NewAssetGraphBuilder() *AssetGraphBuilder {
	return &AssetGraphBuilder{
		nodes: make(map[string]AssetNode),
		edges: make([]AssetEdge, 0),
	}
}

func (g *AssetGraphBuilder) AddNode(id, label, nodeType string, meta map[string]interface{}) {
	if _, exists := g.nodes[id]; !exists {
		g.nodes[id] = AssetNode{
			ID:       id,
			Label:    label,
			Type:     nodeType,
			Metadata: meta,
		}
	}
}

func (g *AssetGraphBuilder) AddEdge(from, to, relation, source string) {
	g.edges = append(g.edges, AssetEdge{
		From:     from,
		To:       to,
		Relation: relation,
		Source:   source,
	})
}

func (g *AssetGraphBuilder) ParseStream(r io.Reader, sourceName string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			var obj map[string]interface{}
			if err := json.Unmarshal([]byte(line), &obj); err == nil {
				val, _ := obj["object_value"].(string)
				if val == "" {
					val, _ = obj["value"].(string)
				}
				t, _ := obj["object_type"].(string)
				if t == "" {
					t, _ = obj["type"].(string)
				}
				if val != "" {
					g.AddNode(val, val, t, obj)
					continue
				}
			}
		}

		var parts []string
		if strings.Contains(line, "\t") {
			parts = strings.Split(line, "\t")
		} else if strings.Contains(line, ",") {
			parts = strings.Split(line, ",")
		} else if strings.Contains(line, ": ") {
			parts = strings.Split(line, ": ")
		}

		if len(parts) >= 2 {
			src := strings.TrimSpace(parts[0])
			dst := strings.TrimSpace(parts[1])
			srcType := "domain"
			if net.ParseIP(src) != nil {
				srcType = "ip"
			}
			dstType := "subdomain"
			if net.ParseIP(dst) != nil {
				dstType = "ip"
			}
			g.AddNode(src, src, srcType, nil)
			g.AddNode(dst, dst, dstType, nil)
			g.AddEdge(src, dst, "resolves_to", sourceName)
			continue
		}

		if net.ParseIP(line) != nil {
			g.AddNode(line, line, "ip", nil)
		} else if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			g.AddNode(line, line, "url", nil)
		} else {
			g.AddNode(line, line, "domain", nil)
		}
	}
}

func (g *AssetGraphBuilder) Build() AssetGraph {
	nodes := make([]AssetNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Label < nodes[j].Label
	})
	return AssetGraph{
		Nodes: nodes,
		Edges: g.edges,
	}
}

// -----------------------------------------------------------------------------
// 2. Snapshot Diff Engine
// -----------------------------------------------------------------------------
func DiffSnapshots(domain string, oldItems, newItems map[string]string) DiffResult {
	allKeysMap := make(map[string]bool)
	for k := range oldItems {
		allKeysMap[k] = true
	}
	for k := range newItems {
		allKeysMap[k] = true
	}

	var allKeys []string
	for k := range allKeysMap {
		allKeys = append(allKeys, k)
	}
	sort.Strings(allKeys)

	var items []DiffItem
	added, removed, modified, unchanged := 0, 0, 0, 0

	for _, k := range allKeys {
		oldVal, hasOld := oldItems[k]
		newVal, hasNew := newItems[k]

		if hasOld && !hasNew {
			removed++
			items = append(items, DiffItem{
				Key:      k,
				Status:   "removed",
				OldValue: oldVal,
				Details:  fmt.Sprintf("Removed: %s", oldVal),
			})
		} else if !hasOld && hasNew {
			added++
			items = append(items, DiffItem{
				Key:      k,
				Status:   "added",
				NewValue: newVal,
				Details:  fmt.Sprintf("Added: %s", newVal),
			})
		} else if oldVal != newVal {
			modified++
			items = append(items, DiffItem{
				Key:      k,
				Status:   "modified",
				OldValue: oldVal,
				NewValue: newVal,
				Details:  fmt.Sprintf("Modified: %s -> %s", oldVal, newVal),
			})
		} else {
			unchanged++
			items = append(items, DiffItem{
				Key:      k,
				Status:   "unchanged",
				OldValue: oldVal,
				NewValue: newVal,
			})
		}
	}

	return DiffResult{
		Domain:         domain,
		ComparedAt:     time.Now().UTC(),
		AddedCount:     added,
		RemovedCount:   removed,
		ModifiedCount:  modified,
		UnchangedCount: unchanged,
		Items:          items,
	}
}

// -----------------------------------------------------------------------------
// 3. Log Triage Engine
// -----------------------------------------------------------------------------
var (
	reCombinedLog = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d{3}) (\d+|-)`)
	reSyslog      = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$`)
	reAuthFail    = regexp.MustCompile(`(?i)(failed password|authentication failure|invalid user|unauthorized|access denied)`)
)

func TriageLogs(r io.Reader) LogTriageSummary {
	scanner := bufio.NewScanner(r)
	totalLines := 0
	authFailures := 0
	statusCodes := make(map[string]int)
	topIPs := make(map[string]int)
	topURIs := make(map[string]int)
	detectedFormat := "generic_text"
	var anomalies []string
	var suspiciousEvents []map[string]any

	for scanner.Scan() {
		totalLines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			detectedFormat = "jsonl"
			var rec map[string]interface{}
			if err := json.Unmarshal([]byte(line), &rec); err == nil {
				if ip, ok := rec["client_ip"].(string); ok {
					topIPs[ip]++
				}
				if st, ok := rec["status"]; ok {
					statusCodes[fmt.Sprintf("%v", st)]++
				}
				if msg, ok := rec["message"].(string); ok && reAuthFail.MatchString(msg) {
					authFailures++
					suspiciousEvents = append(suspiciousEvents, map[string]any{"type": "auth_failure", "message": msg})
				}
				continue
			}
		}

		if m := reCombinedLog.FindStringSubmatch(line); len(m) >= 6 {
			detectedFormat = "http_access"
			cip, uri, st := m[1], m[4], m[5]
			topIPs[cip]++
			topURIs[uri]++
			statusCodes[st]++
			if st == "401" || st == "403" {
				authFailures++
			}
			continue
		}

		if m := reSyslog.FindStringSubmatch(line); len(m) >= 5 {
			detectedFormat = "syslog"
			msg := m[4]
			if reAuthFail.MatchString(msg) {
				authFailures++
				suspiciousEvents = append(suspiciousEvents, map[string]any{"type": "auth_failure", "message": msg})
			}
			continue
		}

		if reAuthFail.MatchString(line) {
			authFailures++
			suspiciousEvents = append(suspiciousEvents, map[string]any{"type": "auth_failure", "message": line})
		}
	}

	if authFailures >= 5 {
		anomalies = append(anomalies, fmt.Sprintf("High-volume authentication failures detected (%d occurrences).", authFailures))
	}
	if statusCodes["404"] > 30 {
		anomalies = append(anomalies, fmt.Sprintf("High rate of HTTP 404 responses (%d) indicating path enumeration.", statusCodes["404"]))
	}

	return LogTriageSummary{
		TotalLines:       totalLines,
		DetectedFormat:   detectedFormat,
		AuthFailures:     authFailures,
		StatusCodes:      statusCodes,
		TopIPs:           topIPs,
		TopURIs:          topURIs,
		Anomalies:        anomalies,
		SuspiciousEvents: suspiciousEvents,
	}
}

// -----------------------------------------------------------------------------
// 4. PCAP Summary
// -----------------------------------------------------------------------------
func SummarizePCAP(filePath string) (PCAPSummary, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return PCAPSummary{}, err
	}

	f, err := os.Open(filePath)
	if err != nil {
		return PCAPSummary{}, err
	}
	defer f.Close()

	var magic uint32
	_ = binary.Read(f, binary.LittleEndian, &magic)

	proto := map[string]int{"Ethernet": 1}
	if magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1 || magic == 0x0a0d0d0a {
		proto["PCAP-Valid-Container"] = 1
	}

	estPackets := info.Size() / 128
	if estPackets == 0 {
		estPackets = 1
	}

	topIPs := make(map[string]int)
	dnsQueries := make(map[string]int)
	tlsSNIs := make(map[string]int)

	// If tshark exists, run fast endpoint dissection
	if tsharkPath, err := exec.LookPath("tshark"); err == nil {
		cmd := exec.Command(tsharkPath, "-r", filePath, "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol")
		if out, err := cmd.Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.Split(line, "\t")
				if len(parts) >= 3 {
					src, dst, pr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
					if src != "" {
						topIPs[src]++
					}
					if dst != "" {
						topIPs[dst]++
					}
					if pr != "" {
						proto[pr]++
					}
				}
			}
		}

		cmdDNS := exec.Command(tsharkPath, "-r", filePath, "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name")
		if outDNS, err := cmdDNS.Output(); err == nil {
			for _, line := range strings.Split(string(outDNS), "\n") {
				q := strings.TrimSpace(line)
				if q != "" {
					dnsQueries[q]++
				}
			}
		}
	}

	return PCAPSummary{
		FilePath:              filePath,
		FilesizeBytes:         info.Size(),
		TotalPacketsEstimated: estPackets,
		Protocols:             proto,
		TopIPs:                topIPs,
		DNSQueries:            dnsQueries,
		TLSSNIHosts:           tlsSNIs,
	}, nil
}

// -----------------------------------------------------------------------------
// 5. Endpoint Inspector
// -----------------------------------------------------------------------------
func InspectEndpoint() EndpointSnapshot {
	hostname, _ := os.Hostname()
	var resolvers []string
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					resolvers = append(resolvers, parts[1])
				}
			}
		}
	}

	var users []string
	if out, err := exec.Command("who").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(line) != "" {
				users = append(users, strings.TrimSpace(line))
			}
		}
	}

	var ports []string
	if out, err := exec.Command("netstat", "-an").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "LISTEN") {
				f := strings.Fields(line)
				if len(f) >= 4 {
					ports = append(ports, f[3])
				}
			}
		}
	}

	var ifaces []string
	if list, err := net.Interfaces(); err == nil {
		for _, iface := range list {
			ifaces = append(ifaces, iface.Name)
		}
	}

	procs := 0
	if out, err := exec.Command("ps", "-e").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 1 {
			procs = len(lines) - 1
		}
	}

	return EndpointSnapshot{
		Hostname:          hostname,
		OS:                "posix",
		Architecture:      "host",
		CollectedAt:       time.Now().UTC(),
		DNSResolvers:      resolvers,
		ActiveUsers:       users,
		ListeningPorts:    ports,
		NetworkInterfaces: ifaces,
		TotalProcesses:    procs,
	}
}

// -----------------------------------------------------------------------------
// 6. Case Packager
// -----------------------------------------------------------------------------
func PackageCase(caseDir, formatType, outPath string) (string, string, error) {
	absDir, err := filepath.Abs(caseDir)
	if err != nil {
		return "", "", err
	}

	if outPath == "" {
		outPath = filepath.Join(absDir, fmt.Sprintf("%s-bundle.%s", filepath.Base(absDir), formatType))
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return "", "", err
	}
	defer outFile.Close()

	h := sha256.New()
	mw := io.MultiWriter(outFile, h)

	if formatType == "zip" {
		zw := zip.NewWriter(mw)
		defer zw.Close()

		err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".sha256") {
				return nil
			}
			rel, _ := filepath.Rel(absDir, path)
			w, err := zw.Create(rel)
			if err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(w, f)
			return err
		})
	} else {
		gw := gzip.NewWriter(mw)
		defer gw.Close()
		tw := tar.NewWriter(gw)
		defer tw.Close()

		err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".zip") || strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".sha256") {
				return nil
			}
			rel, _ := filepath.Rel(absDir, path)
			header, err := tar.FileInfoHeader(info, rel)
			if err != nil {
				return err
			}
			header.Name = rel
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		})
	}

	if err != nil {
		return "", "", err
	}

	digest := hex.EncodeToString(h.Sum(nil))
	chkFile := outPath + ".sha256"
	_ = os.WriteFile(chkFile, []byte(fmt.Sprintf("%s  %s\n", digest, filepath.Base(outPath))), 0644)

	return outPath, digest, nil
}
