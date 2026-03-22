package cve

// Output schema versions — stable contracts for downstream consumers.
const (
	ScanSchemaVersion   = "1.0.0"
	ReportSchemaVersion = "1.0.0"
	ClaimSchemaVersion  = "1.0.0"
	APIVersion          = "1.0.0"
)

// APIInfo returns engine and API version information.
type APIInfo struct {
	EngineVersion       string `json:"engine_version"`
	APIVersion          string `json:"api_version"`
	ScanSchemaVersion   string `json:"scan_schema_version"`
	ReportSchemaVersion string `json:"report_schema_version"`
	ClaimSchemaVersion  string `json:"claim_schema_version"`
}

// GetAPIInfo returns current version information.
func GetAPIInfo() APIInfo {
	return APIInfo{
		EngineVersion:       Version,
		APIVersion:          APIVersion,
		ScanSchemaVersion:   ScanSchemaVersion,
		ReportSchemaVersion: ReportSchemaVersion,
		ClaimSchemaVersion:  ClaimSchemaVersion,
	}
}
