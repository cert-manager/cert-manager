// Package cat provides functionality related to the wire format of CAT
// headers.
package cat

// These header names don't match the spec in terms of their casing, but does
// match what Go will give us from http.CanonicalHeaderKey(). Besides, HTTP
// headers are case insensitive anyway. Rejoice!
const (
	NewRelicIDName         = "X-Newrelic-Id"
	NewRelicTxnName        = "X-Newrelic-Transaction"
	NewRelicAppDataName    = "X-Newrelic-App-Data"
	NewRelicSyntheticsName = "X-Newrelic-Synthetics"
)
