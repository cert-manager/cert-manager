package internal

import (
	"net/http"

	"github.com/newrelic/go-agent/internal/cat"
)

// InboundHTTPRequest adds the inbound request metadata to the TxnCrossProcess.
func (txp *TxnCrossProcess) InboundHTTPRequest(hdr http.Header) error {
	return txp.handleInboundRequestHeaders(HTTPHeaderToMetadata(hdr))
}

// AppDataToHTTPHeader encapsulates the given appData value in the correct HTTP
// header.
func AppDataToHTTPHeader(appData string) http.Header {
	header := http.Header{}

	if appData != "" {
		header.Add(cat.NewRelicAppDataName, appData)
	}

	return header
}

// HTTPHeaderToAppData gets the appData value from the correct HTTP header.
func HTTPHeaderToAppData(header http.Header) string {
	if header == nil {
		return ""
	}

	return header.Get(cat.NewRelicAppDataName)
}

// HTTPHeaderToMetadata gets the cross process metadata from the relevant HTTP
// headers.
func HTTPHeaderToMetadata(header http.Header) CrossProcessMetadata {
	if header == nil {
		return CrossProcessMetadata{}
	}

	return CrossProcessMetadata{
		ID:         header.Get(cat.NewRelicIDName),
		TxnData:    header.Get(cat.NewRelicTxnName),
		Synthetics: header.Get(cat.NewRelicSyntheticsName),
	}
}

// MetadataToHTTPHeader creates a set of HTTP headers to represent the given
// cross process metadata.
func MetadataToHTTPHeader(metadata CrossProcessMetadata) http.Header {
	header := http.Header{}

	if metadata.ID != "" {
		header.Add(cat.NewRelicIDName, metadata.ID)
	}

	if metadata.TxnData != "" {
		header.Add(cat.NewRelicTxnName, metadata.TxnData)
	}

	if metadata.Synthetics != "" {
		header.Add(cat.NewRelicSyntheticsName, metadata.Synthetics)
	}

	return header
}
