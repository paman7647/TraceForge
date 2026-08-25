package main

import "time"

// Indicator represents an extracted observable / IOC.
type Indicator struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Defanged   string    `json:"defanged,omitempty"`
	Source     string    `json:"source"`
	Confidence string    `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Tags       []string  `json:"tags,omitempty"`
}

// Evidence represents an indexed evidence file with cryptographic checksums.
type Evidence struct {
	ID           string    `json:"id"`
	RelativePath string    `json:"relative_path"`
	Filename     string    `json:"filename"`
	SizeBytes    int64     `json:"size_bytes"`
	MIMEType     string    `json:"mime_type"`
	SHA256       string    `json:"sha256"`
	MD5          string    `json:"md5,omitempty"`
	MTime        time.Time `json:"mtime"`
	IsSymlink    bool      `json:"is_symlink"`
	Description  string    `json:"description,omitempty"`
}

// Event represents a normalized timeline milestone.
type Event struct {
	ID                string    `json:"id"`
	TimestampUTC      time.Time `json:"timestamp_utc"`
	OriginalTimestamp string    `json:"original_timestamp"`
	Source            string    `json:"source"`
	Type              string    `json:"type"`
	Severity          string    `json:"severity"`
	Description       string    `json:"description"`
}

// Finding represents an analytical discovery.
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Observation represents a raw intelligence entity observation.
type Observation struct {
	Source      string                 `json:"source"`
	ObjectType  string                 `json:"object_type"`
	ObjectValue string                 `json:"object_value"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Confidence  string                 `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Relationship models a cross-domain correlation between entities.
type Relationship struct {
	Source          string `json:"source"`
	Target          string `json:"target"`
	SharedIndicator string `json:"shared_indicator"`
	Type            string `json:"type"`
	Relation        string `json:"relation"`
}

// AssetNode models a vertex in the asset graph.
type AssetNode struct {
	ID       string                 `json:"id"`
	Label    string                 `json:"label"`
	Type     string                 `json:"type"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AssetEdge models a directed relationship between vertices.
type AssetEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
	Source   string `json:"source"`
}

// AssetGraph represents a network topology of intelligence entities.
type AssetGraph struct {
	Nodes []AssetNode `json:"nodes"`
	Edges []AssetEdge `json:"edges"`
}

// DiffItem models a change between two intelligence snapshots.
type DiffItem struct {
	Key      string `json:"key"`
	Status   string `json:"status"` // added, removed, modified, unchanged
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	Details  string `json:"details,omitempty"`
}

// DiffResult contains aggregated snapshot comparison metrics.
type DiffResult struct {
	Domain         string     `json:"domain"`
	ComparedAt     time.Time  `json:"compared_at"`
	AddedCount     int        `json:"added_count"`
	RemovedCount   int        `json:"removed_count"`
	ModifiedCount  int        `json:"modified_count"`
	UnchangedCount int        `json:"unchanged_count"`
	Items          []DiffItem `json:"items"`
}

// LogTriageSummary models aggregated log stream anomalies.
type LogTriageSummary struct {
	TotalLines       int              `json:"total_lines"`
	DetectedFormat   string           `json:"detected_format"`
	AuthFailures     int              `json:"auth_failures"`
	StatusCodes      map[string]int   `json:"status_codes"`
	TopIPs           map[string]int   `json:"top_ips"`
	TopURIs          map[string]int   `json:"top_uris"`
	Anomalies        []string         `json:"anomalies"`
	SuspiciousEvents []map[string]any `json:"suspicious_events"`
}

// EndpointSnapshot models host environment posture.
type EndpointSnapshot struct {
	Hostname          string    `json:"hostname"`
	OS                string    `json:"os"`
	Architecture      string    `json:"architecture"`
	CollectedAt       time.Time `json:"collected_at"`
	DNSResolvers      []string  `json:"dns_resolvers"`
	ActiveUsers       []string  `json:"active_users"`
	ListeningPorts    []string  `json:"listening_ports"`
	NetworkInterfaces []string  `json:"network_interfaces"`
	TotalProcesses    int       `json:"total_processes"`
}

// PCAPSummary models packet capture protocol dissection.
type PCAPSummary struct {
	FilePath              string         `json:"filepath"`
	FilesizeBytes         int64          `json:"filesize_bytes"`
	TotalPacketsEstimated int64          `json:"total_packets_estimated"`
	Protocols             map[string]int `json:"protocols"`
	TopIPs                map[string]int `json:"top_ips"`
	DNSQueries            map[string]int `json:"dns_queries"`
	TLSSNIHosts           map[string]int `json:"tls_sni_hosts"`
}

// CaseSummary models high-level workspace metrics.
type CaseSummary struct {
	CaseID                string    `json:"case_id"`
	CaseName              string    `json:"case_name"`
	Analyst               string    `json:"analyst"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
	TotalEvidence         int       `json:"total_evidence"`
	TotalFindings         int       `json:"total_findings"`
	HighSeverityFindings  int       `json:"high_severity_findings"`
	TotalIOCs             int       `json:"total_iocs"`
	UniqueIPs             int       `json:"unique_ips"`
	UniqueDomains         int       `json:"unique_domains"`
	UniqueEmails          int       `json:"unique_emails"`
	TotalTimelineEvents   int       `json:"total_timeline_events"`
}
