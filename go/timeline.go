package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

var timeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"Jan 02 15:04:05",
	"Jan  2 15:04:05",
	"2006-01-02",
}

// ParseUTCTimestamp parses various timestamp formats and returns UTC time.
func ParseUTCTimestamp(ts string) (time.Time, error) {
	ts = strings.TrimSpace(ts)
	for _, layout := range timeFormats {
		t, err := time.Parse(layout, ts)
		if err == nil {
			if t.Year() == 0 {
				t = t.AddDate(time.Now().Year(), 0, 0)
			}
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp: %q", ts)
}

// NormalizeTimeline sorts events chronologically and filters by severity.
func NormalizeTimeline(events []Event, minSeverity string) []Event {
	sevRank := map[string]int{
		"info":     1,
		"low":      2,
		"medium":   3,
		"high":     4,
		"critical": 5,
	}

	minRank := sevRank[strings.ToLower(minSeverity)]
	if minRank == 0 {
		minRank = 1
	}

	var filtered []Event
	for i, e := range events {
		if e.ID == "" {
			e.ID = fmt.Sprintf("EVT-%04d", i+1)
		}
		if e.Severity == "" {
			e.Severity = "info"
		}
		if sevRank[strings.ToLower(e.Severity)] < minRank {
			continue
		}
		if e.TimestampUTC.IsZero() && e.OriginalTimestamp != "" {
			parsed, err := ParseUTCTimestamp(e.OriginalTimestamp)
			if err == nil {
				e.TimestampUTC = parsed
			}
		}
		filtered = append(filtered, e)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].TimestampUTC.Before(filtered[j].TimestampUTC)
	})

	return filtered
}
