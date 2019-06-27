package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	newrelic "github.com/newrelic/go-agent"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/logging"
)

// Middleware is a function returns another http.Handler that wraps the given
// handler.
type Middleware func(next http.Handler) http.Handler

// Monitoring is the type holding a middleware that traces the request to an
// application.
type Monitoring struct {
	middleware Middleware
}

// monitoring config represents the JSON attributes used for configuration. At
// this moment only fields for NewRelic are supported.
type monitoringConfig struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// New initializes the monitoring with the given configuration.
// Right now it only supports newrelic as the monitoring backend.
func New(raw json.RawMessage) (*Monitoring, error) {
	var config monitoringConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling monitoring attribute")
	}

	m := new(Monitoring)
	switch strings.ToLower(config.Type) {
	case "", "newrelic":
		app, err := newrelic.NewApplication(newrelic.NewConfig(config.Name, config.Key))
		if err != nil {
			return nil, errors.Wrap(err, "error loading New Relic application")
		}
		m.middleware = newRelicMiddleware(app)
	default:
		return nil, errors.Errorf("unsupported monitoring.type '%s'", config.Type)
	}
	return m, nil
}

// Middleware is an HTTP middleware that traces the request with the configured
// monitoring backednd.
func (m *Monitoring) Middleware(next http.Handler) http.Handler {
	return m.middleware(next)
}

func newRelicMiddleware(app newrelic.Application) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start transaction
			txn := app.StartTransaction(transactionName(r), w, r)
			defer txn.End()

			// Wrap request writer if necessary
			rw := logging.NewResponseLogger(w)

			// Call next handler
			next.ServeHTTP(rw, r)

			// Report status (using same key NewRelic uses by default)
			status := rw.StatusCode()
			txn.AddAttribute("httpResponseCode", strconv.Itoa(status))

			// Add custom attributes
			if v, ok := logging.GetRequestID(r.Context()); ok {
				txn.AddAttribute("request.id", v)
			}

			// Report errors if necessary
			if status >= http.StatusBadRequest {
				var errorNoticed bool
				if fields := rw.Fields(); fields != nil {
					if v, ok := fields["error"]; ok {
						if err, ok := v.(error); ok {
							txn.NoticeError(err)
							errorNoticed = true
						}
					}
				}
				if !errorNoticed {
					txn.NoticeError(fmt.Errorf("request failed with status code %d", status))
				}
			}
		})
	}
}

func transactionName(r *http.Request) string {
	// From https://github.com/gorilla/handlers
	uri := r.RequestURI
	// Requests using the CONNECT method over HTTP/2.0 must use
	// the authority field (aka r.Host) to identify the target.
	// Refer: https://httpwg.github.io/specs/rfc7540.html#CONNECT
	if r.ProtoMajor == 2 && r.Method == "CONNECT" {
		uri = r.Host
	}
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	return uri
}
