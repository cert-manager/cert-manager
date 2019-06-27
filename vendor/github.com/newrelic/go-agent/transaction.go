package newrelic

import (
	"net/http"
	"net/url"
)

// Transaction instruments one logical unit of work: either an inbound web
// request or background task.  Start a new Transaction with the
// Application.StartTransaction() method.
type Transaction interface {
	// The transaction's http.ResponseWriter methods delegate to the
	// http.ResponseWriter provided as a parameter to
	// Application.StartTransaction or Transaction.SetWebResponse.  This
	// allows instrumentation of the response code and response headers.
	// These methods may be called safely if the transaction does not have a
	// http.ResponseWriter.
	http.ResponseWriter

	// End finishes the Transaction.  After that, subsequent calls to End or
	// other Transaction methods have no effect.  All segments and
	// instrumentation must be completed before End is called.
	End() error

	// Ignore prevents this transaction's data from being recorded.
	Ignore() error

	// SetName names the transaction.  Use a limited set of unique names to
	// ensure that Transactions are grouped usefully.
	SetName(name string) error

	// NoticeError records an error.  The Transaction saves the first five
	// errors.  For more control over the recorded error fields, see the
	// newrelic.Error type.
	NoticeError(err error) error

	// AddAttribute adds a key value pair to the transaction event, errors,
	// and traces.
	//
	// The key must contain fewer than than 255 bytes.  The value must be a
	// number, string, or boolean.
	//
	// For more information, see:
	// https://docs.newrelic.com/docs/agents/manage-apm-agents/agent-metrics/collect-custom-attributes
	AddAttribute(key string, value interface{}) error

	// SetWebRequest marks the transaction as a web transaction.  If
	// WebRequest is non-nil, SetWebRequest will additionally collect
	// details on request attributes, url, and method.  If headers are
	// present, the agent will look for a distributed tracing header.  Use
	// NewWebRequest to transform a *http.Request into a WebRequest.
	SetWebRequest(WebRequest) error

	// SetWebResponse sets transaction's http.ResponseWriter.  After calling
	// this method, the transaction may be used in place of the
	// ResponseWriter to intercept the response code.  This method is useful
	// when the ResponseWriter is not available at the beginning of the
	// transaction (if so, it can be given as a parameter to
	// Application.StartTransaction).  This method will return a reference
	// to the transaction which implements the combination of
	// http.CloseNotifier, http.Flusher, http.Hijacker, and io.ReaderFrom
	// implemented by the ResponseWriter.
	SetWebResponse(http.ResponseWriter) Transaction

	// StartSegmentNow starts timing a segment.  The SegmentStartTime
	// returned can be used as the StartTime field in Segment,
	// DatastoreSegment, or ExternalSegment.  We recommend using the
	// StartSegmentNow function instead of this method since it checks if
	// the Transaction is nil.
	StartSegmentNow() SegmentStartTime

	// CreateDistributedTracePayload creates a payload used to link
	// transactions.  CreateDistributedTracePayload should be called every
	// time an outbound call is made since the payload contains a timestamp.
	//
	// StartExternalSegment calls CreateDistributedTracePayload, so you
	// don't need to use it for outbound HTTP calls: Just use
	// StartExternalSegment!
	//
	// This method never returns nil.  If the application is disabled or not
	// yet connected then this method returns a shim implementation whose
	// methods return empty strings.
	CreateDistributedTracePayload() DistributedTracePayload

	// AcceptDistributedTracePayload links transactions by accepting a
	// distributed trace payload from another transaction.
	//
	// Application.StartTransaction calls this method automatically if a
	// payload is present in the request headers.  Therefore, this method
	// does not need to be used for typical HTTP transactions.
	//
	// AcceptDistributedTracePayload should be used as early in the
	// transaction as possible.  It may not be called after a call to
	// CreateDistributedTracePayload.
	//
	// The payload parameter may be a DistributedTracePayload, a string, or
	// a []byte.
	AcceptDistributedTracePayload(t TransportType, payload interface{}) error

	// Application returns the Application which started the transaction.
	Application() Application

	// BrowserTimingHeader generates the JavaScript required to enable New
	// Relic's Browser product.  This code should be placed into your pages
	// as close to the top of the <head> element as possible, but after any
	// position-sensitive <meta> tags (for example, X-UA-Compatible or
	// charset information).
	//
	// This function freezes the transaction name: any calls to SetName()
	// after BrowserTimingHeader() will be ignored.
	//
	// The *BrowserTimingHeader return value will be nil if browser
	// monitoring is disabled, the application is not connected, or an error
	// occurred.  It is safe to call the pointer's methods if it is nil.
	BrowserTimingHeader() (*BrowserTimingHeader, error)

	// NewGoroutine allows you to use the Transaction in multiple
	// goroutines.
	//
	// Each goroutine must have its own Transaction reference returned by
	// NewGoroutine.  You must call NewGoroutine to get a new Transaction
	// reference every time you wish to pass the Transaction to another
	// goroutine. It does not matter if you call this before or after the
	// other goroutine has started.
	//
	// All Transaction methods can be used in any Transaction reference.
	// The Transaction will end when End() is called in any goroutine.
	//
	// Example passing a new Transaction reference directly to another
	// goroutine:
	//
	//	go func(txn newrelic.Transaction) {
	//		defer newrelic.StartSegment(txn, "async").End()
	//		time.Sleep(100 * time.Millisecond)
	//	}(txn.NewGoroutine())
	//
	// Example passing a new Transaction reference on a channel to another
	// goroutine:
	//
	//	ch := make(chan newrelic.Transaction)
	//	go func() {
	//		txn := <-ch
	//		defer newrelic.StartSegment(txn, "async").End()
	//		time.Sleep(100 * time.Millisecond)
	//	}()
	//	ch <- txn.NewGoroutine()
	//
	NewGoroutine() Transaction
}

// DistributedTracePayload traces requests between applications or processes.
// DistributedTracePayloads are automatically added to HTTP requests by
// StartExternalSegment, so you only need to use this if you are tracing through
// a message queue or another non-HTTP communication library.  The
// DistributedTracePayload may be marshalled in one of two formats: HTTPSafe or
// Text.  All New Relic agents can accept payloads in either format.
type DistributedTracePayload interface {
	// HTTPSafe serializes the payload into a string containing http safe
	// characters.
	HTTPSafe() string
	// Text serializes the payload into a string.  The format is slightly
	// more compact than HTTPSafe.
	Text() string
}

const (
	// DistributedTracePayloadHeader is the header used by New Relic agents
	// for automatic trace payload instrumentation.
	DistributedTracePayloadHeader = "Newrelic"
)

// TransportType is used in Transaction.AcceptDistributedTracePayload() to
// represent the type of connection that the trace payload was transported over.
type TransportType struct{ name string }

// TransportType names used across New Relic agents:
var (
	TransportUnknown = TransportType{name: "Unknown"}
	TransportHTTP    = TransportType{name: "HTTP"}
	TransportHTTPS   = TransportType{name: "HTTPS"}
	TransportKafka   = TransportType{name: "Kafka"}
	TransportJMS     = TransportType{name: "JMS"}
	TransportIronMQ  = TransportType{name: "IronMQ"}
	TransportAMQP    = TransportType{name: "AMQP"}
	TransportQueue   = TransportType{name: "Queue"}
	TransportOther   = TransportType{name: "Other"}
)

// WebRequest may be implemented to provide request information to
// Transaction.SetWebRequest.
type WebRequest interface {
	// Header may return nil if you don't have any headers or don't want to
	// transform them to http.Header format.
	Header() http.Header
	// URL may return nil if you don't have a URL or don't want to transform
	// it to *url.URL.
	URL() *url.URL
	Method() string
	// If a distributed tracing header is found in the headers returned by
	// Header(), this TransportType will be used in the distributed tracing
	// metrics.
	Transport() TransportType
}

// NewWebRequest turns a *http.Request into a WebRequest for input into
// Transaction.SetWebRequest.
func NewWebRequest(request *http.Request) WebRequest {
	if nil == request {
		return nil
	}
	return requestWrap{request: request}
}
