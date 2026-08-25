package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

// OutputFormat represents the desired output serialization.
type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
	FormatJSONL OutputFormat = "jsonl"
	FormatCSV   OutputFormat = "csv"
	FormatHTML  OutputFormat = "html"
)

// SanitizeCSVCell prevents CSV formula injection in spreadsheet software.
func SanitizeCSVCell(val string) string {
	if len(val) == 0 {
		return val
	}
	first := val[0]
	if first == '=' || first == '+' || first == '-' || first == '@' || first == '\t' || first == '\r' {
		return "'" + val
	}
	return val
}

// PrintJSON writes indented JSON to stdout.
func PrintJSON(data interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// PrintJSONL writes a slice of objects as newline-delimited JSON.
func PrintJSONL(items []interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

// NewTableWriter initializes a tabwriter for aligned terminal output.
func NewTableWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
}

// WriteCSV exports data rows with automatic formula injection sanitization.
func WriteCSV(w io.Writer, headers []string, rows [][]string) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	sanitizedHeaders := make([]string, len(headers))
	for i, h := range headers {
		sanitizedHeaders[i] = SanitizeCSVCell(h)
	}
	if err := cw.Write(sanitizedHeaders); err != nil {
		return err
	}

	for _, row := range rows {
		sanitizedRow := make([]string, len(row))
		for i, cell := range row {
			sanitizedRow[i] = SanitizeCSVCell(cell)
		}
		if err := cw.Write(sanitizedRow); err != nil {
			return err
		}
	}
	return nil
}

// RenderAssetGraphHTML generates a standalone interactive HTML graph.
func RenderAssetGraphHTML(graph AssetGraph, title string) string {
	var rows strings.Builder
	for _, n := range graph.Nodes {
		var conns []string
		for _, e := range graph.Edges {
			if e.From == n.ID {
				conns = append(conns, fmt.Sprintf("&rarr; %s (%s)", e.To, e.Relation))
			}
			if e.To == n.ID {
				conns = append(conns, fmt.Sprintf("&larr; %s (%s)", e.From, e.Relation))
			}
		}
		connStr := strings.Join(conns, "<br>")
		if connStr == "" {
			connStr = "<span style='color:#64748b'>Standalone</span>"
		}
		rows.WriteString(fmt.Sprintf("<tr><td><strong>%s</strong></td><td><span class='badge badge-%s'>%s</span></td><td>%s</td></tr>\n",
			n.Label, n.Type, n.Type, connStr))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%s</title>
<style>
body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; padding: 24px; margin: 0; }
h1 { color: #38bdf8; font-size: 20px; border-bottom: 1px solid #334155; padding-bottom: 12px; }
.stats { display: flex; gap: 16px; margin: 16px 0; }
.stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 12px 16px; min-width: 140px; }
.stat-val { font-size: 20px; font-weight: bold; color: #38bdf8; }
table { width: 100%%; border-collapse: collapse; background: #1e293b; border-radius: 6px; overflow: hidden; margin-top: 16px; }
th { background: #0b132b; color: #94a3b8; text-align: left; padding: 10px 14px; font-size: 11px; text-transform: uppercase; }
td { padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 13px; }
tr:hover { background: #273549; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }
.badge-domain { background: #0369a1; color: #e0f2fe; }
.badge-ip { background: #15803d; color: #dcfce7; }
.badge-url { background: #a21caf; color: #fae8ff; }
.badge-subdomain { background: #b45309; color: #fef3c7; }
</style>
</head>
<body>
<h1>%s</h1>
<div class="stats">
  <div class="stat-card"><div>Entities</div><div class="stat-val">%d</div></div>
  <div class="stat-card"><div>Relationships</div><div class="stat-val">%d</div></div>
</div>
<table>
<thead><tr><th>Entity Label</th><th>Type</th><th>Observed Relationships</th></tr></thead>
<tbody>
%s
</tbody>
</table>
</body>
</html>`, title, title, len(graph.Nodes), len(graph.Edges), rows.String())
}
