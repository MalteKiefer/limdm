package api

import _ "embed"

// OsqueryKey is the osquery repository signing key (fingerprint
// 1484 120A C4E9 F8A1 A577 AEEE 97A8 0C63 C9D8 B80B), shared by the agent and
// the install script the server generates.
//
//go:embed osquery.asc
var OsqueryKey string
