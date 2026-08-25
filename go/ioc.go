package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	reIPv4   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	reIPv6   = regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b`)
	reEmail  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	reURL    = regexp.MustCompile(`https?://[^\s<>"'{}|\\^` + "`" + `]+`)
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	reSHA256 = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	reSHA1   = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	reMD5    = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	reCVE    = regexp.MustCompile(`\bCVE-[0-9]{4}-[0-9]{4,8}\b`)
)

// DefangIOC converts live actionable indicators into inert text.
func DefangIOC(iocType, val string) string {
	switch iocType {
	case "url":
		res := strings.ReplaceAll(val, "http://", "hxxp://")
		res = strings.ReplaceAll(res, "https://", "hxxps://")
		return strings.ReplaceAll(res, ".", "[.]")
	case "domain", "ipv4", "ipv6", "ip":
		return strings.ReplaceAll(val, ".", "[.]")
	case "email":
		res := strings.ReplaceAll(val, "@", "[at]")
		return strings.ReplaceAll(res, ".", "[.]")
	default:
		return val
	}
}

// ExtractIOCs scans raw text, extracting and deduplicating indicators.
func ExtractIOCs(content, source string) []Indicator {
	now := time.Now().UTC()
	iocMap := make(map[string]Indicator)

	addIOC := func(t, val, conf string) {
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		if t == "ipv4" {
			ip := net.ParseIP(val)
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
				return
			}
		}
		if t == "domain" {
			val = strings.ToLower(val)
			if strings.HasSuffix(val, ".local") || strings.HasSuffix(val, ".internal") || strings.HasSuffix(val, ".arpa") {
				return
			}
		}

		key := fmt.Sprintf("%s:%s", t, val)
		if existing, exists := iocMap[key]; exists {
			existing.LastSeen = now
			iocMap[key] = existing
			return
		}

		h := sha256.Sum256([]byte(key))
		id := fmt.Sprintf("IOC-%s", strings.ToUpper(hex.EncodeToString(h[:4])))

		iocMap[key] = Indicator{
			ID:         id,
			Type:       t,
			Value:      val,
			Defanged:   DefangIOC(t, val),
			Source:     source,
			Confidence: conf,
			FirstSeen:  now,
			LastSeen:   now,
		}
	}

	// URLs
	for _, m := range reURL.FindAllString(content, -1) {
		addIOC("url", m, "high")
		if u, err := url.Parse(m); err == nil && u.Hostname() != "" {
			if net.ParseIP(u.Hostname()) != nil {
				addIOC("ipv4", u.Hostname(), "high")
			} else {
				addIOC("domain", u.Hostname(), "high")
			}
		}
	}

	// Emails
	for _, m := range reEmail.FindAllString(content, -1) {
		addIOC("email", m, "high")
	}

	// IPs
	for _, m := range reIPv4.FindAllString(content, -1) {
		addIOC("ipv4", m, "high")
	}
	for _, m := range reIPv6.FindAllString(content, -1) {
		addIOC("ipv6", m, "high")
	}

	// Hashes
	for _, m := range reSHA256.FindAllString(content, -1) {
		addIOC("sha256", strings.ToLower(m), "high")
	}
	for _, m := range reSHA1.FindAllString(content, -1) {
		addIOC("sha1", strings.ToLower(m), "medium")
	}
	for _, m := range reMD5.FindAllString(content, -1) {
		addIOC("md5", strings.ToLower(m), "medium")
	}

	// CVEs
	for _, m := range reCVE.FindAllString(content, -1) {
		addIOC("cve", m, "high")
	}

	// Domains
	for _, m := range reDomain.FindAllString(content, -1) {
		if net.ParseIP(m) == nil && !strings.Contains(content, "@"+m) {
			addIOC("domain", strings.ToLower(m), "medium")
		}
	}

	var results []Indicator
	for _, ioc := range iocMap {
		results = append(results, ioc)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Type == results[j].Type {
			return results[i].Value < results[j].Value
		}
		return results[i].Type < results[j].Type
	})

	return results
}
