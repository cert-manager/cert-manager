package newrelic

import (
	"net/http"
	"time"
)

// Application represents your application.
type Application interface {
	// StartTransaction begins a Transaction.
	// * Transaction.NewGoroutine() must be used to pass the Transaction
	//   between goroutines.
	// * This method never returns nil.
	// * The Transaction is considered a web transaction if an http.Request
	//   is provided.
	// * The transaction returned implements the http.ResponseWriter
	//   interface.  Provide your ResponseWriter as a parameter and
	//   then use the Transaction in its place to instrument the response
	//   code and response headers.
	StartTransaction(name string, w http.ResponseWriter, r *http.Request) Transaction

	// RecordCustomEvent adds a custom event.
	//
	// eventType must consist of alphanumeric characters, underscores, and
	// colons, and must contain fewer than 255 bytes.
	//
	// Each value in the params map must be a number, string, or boolean.
	// Keys must be less than 255 bytes.  The params map may not contain
	// more than 64 attributes.  For more information, and a set of
	// restricted keywords, see:
	//
	// https://docs.newrelic.com/docs/insights/new-relic-insights/adding-querying-data/inserting-custom-events-new-relic-apm-agents
	//
	// An error is returned if event type or params is invalid.
	RecordCustomEvent(eventType string, params map[string]interface{}) error

	// RecordCustomMetric records a custom metric.  The metric name you
	// provide will be prefixed by "Custom/".
	//
	// https://docs.newrelic.com/docs/agents/manage-apm-agents/agent-data/collect-custom-metrics
	RecordCustomMetric(name string, value float64) error

	// WaitForConnection blocks until the application is connected, is
	// incapable of being connected, or the timeout has been reached.  This
	// method is useful for short-lived processes since the application will
	// not gather data until it is connected.  nil is returned if the
	// application is connected successfully.
	WaitForConnection(timeout time.Duration) error

	// Shutdown flushes data to New Relic's servers and stops all
	// agent-related goroutines managing this application.  After Shutdown
	// is called, The application is disabled and will never collect data
	// again.  This method blocks until all final data is sent to New Relic
	// or the timeout has elapsed.  Increase the timeout and check debug
	// logs if you aren't seeing data.
	Shutdown(timeout time.Duration)
}

// NewApplication creates an Application and spawns goroutines to manage the
// aggregation and harvesting of data.  On success, a non-nil Application and a
// nil error are returned. On failure, a nil Application and a non-nil error
// are returned. Applications do not share global state, therefore it is safe
// to create multiple applications.
func NewApplication(c Config) (Application, error) {
	return newApp(c)
}
