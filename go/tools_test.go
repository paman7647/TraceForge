package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractIOCs(t *testing.T) {
	raw := `Found bad actor admin@evil.org on IP 198.51.100.25 and URL https://malicious.cc/drop.exe with CVE-2023-9999`
	iocs := ExtractIOCs(raw, "test_input")

	types := make(map[string]bool)
	for _, ioc := range iocs {
		types[ioc.Type] = true
	}

	if !types["email"] {
		t.Errorf("Expected email IOC")
	}
	if !types["ipv4"] {
		t.Errorf("Expected ipv4 IOC")
	}
	if !types["url"] {
		t.Errorf("Expected url IOC")
	}
	if !types["cve"] {
		t.Errorf("Expected cve IOC")
	}
}

func TestDefangIOC(t *testing.T) {
	if got := DefangIOC("ipv4", "1.2.3.4"); got != "1[.]2[.]3[.]4" {
		t.Errorf("Unexpected defanged IP: %s", got)
	}
	if got := DefangIOC("email", "a@b.com"); got != "a[at]b[.]com" {
		t.Errorf("Unexpected defanged email: %s", got)
	}
	if got := DefangIOC("url", "https://evil.com/x"); got != "hxxps://evil[.]com/x" {
		t.Errorf("Unexpected defanged URL: %s", got)
	}
}

func TestDiffSnapshots(t *testing.T) {
	oldMap := map[string]string{"a.com": "1.1.1.1", "b.com": "2.2.2.2"}
	newMap := map[string]string{"a.com": "1.1.1.1", "c.com": "3.3.3.3"}

	res := DiffSnapshots("test_dns", oldMap, newMap)
	if res.AddedCount != 1 || res.RemovedCount != 1 || res.UnchangedCount != 1 {
		t.Errorf("Unexpected diff count: added=%d, removed=%d, unchanged=%d", res.AddedCount, res.RemovedCount, res.UnchangedCount)
	}
}

func TestNormalizeTimeline(t *testing.T) {
	events := []Event{
		{OriginalTimestamp: "2026-08-25 12:00:00", Severity: "low", Description: "Event 2"},
		{OriginalTimestamp: "2026-08-25 10:00:00", Severity: "high", Description: "Event 1"},
	}

	res := NormalizeTimeline(events, "info")
	if len(res) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(res))
	}
	if res[0].Description != "Event 1" {
		t.Errorf("Expected Event 1 to be first chronologically")
	}
}

func TestSanitizeCSVCell(t *testing.T) {
	unsafe := "=cmd|' /C calc'!A0"
	safe := SanitizeCSVCell(unsafe)
	if !strings.HasPrefix(safe, "'") {
		t.Errorf("Formula injection was not sanitized: %s", safe)
	}
}

func TestIndexEvidenceDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "evidence_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	f1 := filepath.Join(tmpDir, "sample.txt")
	_ = os.WriteFile(f1, []byte("evidence content"), 0644)

	items, err := IndexEvidenceDirectory(tmpDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(items))
	}
	if items[0].SHA256 == "" || items[0].SHA256 == "-" {
		t.Errorf("Expected valid SHA-256 digest")
	}
}

func TestTriageLogs(t *testing.T) {
	logData := `192.168.1.10 - - [25/Aug/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 401 128
192.168.1.10 - - [25/Aug/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401 128
192.168.1.10 - - [25/Aug/2026:10:00:02 +0000] "POST /login HTTP/1.1" 401 128
192.168.1.10 - - [25/Aug/2026:10:00:03 +0000] "POST /login HTTP/1.1" 401 128
192.168.1.10 - - [25/Aug/2026:10:00:04 +0000] "POST /login HTTP/1.1" 401 128
`
	res := TriageLogs(strings.NewReader(logData))
	if res.AuthFailures < 5 {
		t.Errorf("Expected at least 5 auth failures, got %d", res.AuthFailures)
	}
}

func TestAssetGraph(t *testing.T) {
	raw := `target.org, 93.184.216.34
api.target.org, 93.184.216.35
`
	builder := NewAssetGraphBuilder()
	builder.ParseStream(strings.NewReader(raw), "test")
	graph := builder.Build()

	if len(graph.Nodes) < 4 {
		t.Errorf("Expected at least 4 nodes, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 2 {
		t.Errorf("Expected 2 edges, got %d", len(graph.Edges))
	}

	html := RenderAssetGraphHTML(graph, "Test Graph")
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("Expected valid HTML document")
	}
}

func TestPackageCase(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "case_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	_ = os.WriteFile(filepath.Join(tmpDir, "case.json"), []byte(`{"case_id":"CASE-001"}`), 0644)
	outZip := filepath.Join(tmpDir, "test.zip")

	pkg, digest, err := PackageCase(tmpDir, "zip", outZip)
	if err != nil {
		t.Fatal(err)
	}
	if pkg != outZip || len(digest) != 64 {
		t.Errorf("Invalid package result: %s, digest: %s", pkg, digest)
	}
}
