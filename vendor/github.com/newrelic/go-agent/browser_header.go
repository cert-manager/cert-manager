package newrelic

import (
	"encoding/json"
)

var (
	browserStartTag   = []byte(`<script type="text/javascript">`)
	browserEndTag     = []byte(`</script>`)
	browserInfoPrefix = []byte(`window.NREUM||(NREUM={});NREUM.info=`)
)

// browserInfo contains the fields that are marshalled into the Browser agent's
// info hash.
//
// https://newrelic.atlassian.net/wiki/spaces/eng/pages/50299103/BAM+Agent+Auto-Instrumentation
type browserInfo struct {
	Beacon                string `json:"beacon"`
	LicenseKey            string `json:"licenseKey"`
	ApplicationID         string `json:"applicationID"`
	TransactionName       string `json:"transactionName"`
	QueueTimeMillis       int64  `json:"queueTime"`
	ApplicationTimeMillis int64  `json:"applicationTime"`
	ObfuscatedAttributes  string `json:"atts"`
	ErrorBeacon           string `json:"errorBeacon"`
	Agent                 string `json:"agent"`
}

// BrowserTimingHeader encapsulates the JavaScript required to enable New
// Relic's Browser product.
type BrowserTimingHeader struct {
	agentLoader string
	info        browserInfo
}

func appendSlices(slices ...[]byte) []byte {
	length := 0
	for _, s := range slices {
		length += len(s)
	}
	combined := make([]byte, 0, length)
	for _, s := range slices {
		combined = append(combined, s...)
	}
	return combined
}

// WithTags returns the browser timing JavaScript which includes the enclosing
// <script> and </script> tags.  This method returns nil if the receiver is
// nil, the feature is disabled, the application is not yet connected, or an
// error occurs.  The byte slice returned is in UTF-8 format.
func (h *BrowserTimingHeader) WithTags() []byte {
	withoutTags := h.WithoutTags()
	if nil == withoutTags {
		return nil
	}
	return appendSlices(browserStartTag, withoutTags, browserEndTag)
}

// WithoutTags returns the browser timing JavaScript without any enclosing tags,
// which may then be embedded within any JavaScript code.  This method returns
// nil if the receiver is nil, the feature is disabled, the application is not
// yet connected, or an error occurs.  The byte slice returned is in UTF-8
// format.
func (h *BrowserTimingHeader) WithoutTags() []byte {
	if nil == h {
		return nil
	}

	// We could memoise this, but it seems unnecessary, since most users are
	// going to call this zero or one times.
	info, err := json.Marshal(h.info)
	if err != nil {
		// There's no way to log from here, but this also should be unreachable in
		// practice.
		return nil
	}

	return appendSlices([]byte(h.agentLoader), browserInfoPrefix, info)
}
