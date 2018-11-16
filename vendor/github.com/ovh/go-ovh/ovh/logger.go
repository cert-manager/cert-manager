package ovh

import (
	"net/http"
)

// Logger is the interface that should be implemented for loggers that wish to
// log HTTP requests and HTTP responses.
type Logger interface {
	// LogRequest logs an HTTP request.
	LogRequest(*http.Request)

	// LogResponse logs an HTTP response.
	LogResponse(*http.Response)
}
