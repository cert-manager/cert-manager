package logging

import (
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// LoggerHandler creates a logger handler
type LoggerHandler struct {
	name   string
	logger *logrus.Logger
	next   http.Handler
}

// NewLoggerHandler returns the given http.Handler with the logger integrated.
func NewLoggerHandler(name string, logger *Logger, next http.Handler) http.Handler {
	h := RequestID(logger.GetTraceHeader())
	return h(&LoggerHandler{
		name:   name,
		logger: logger.GetImpl(),
		next:   next,
	})
}

// ServeHTTP implements the http.Handler and call to the handler to log with a
// custom http.ResponseWriter that records the response code and the number of
// bytes sent.
func (l *LoggerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := time.Now()
	rw := NewResponseLogger(w)
	l.next.ServeHTTP(rw, r)
	d := time.Now().Sub(t)
	l.writeEntry(rw, r, t, d)
}

// writeEntry writes to the Logger writer the request information in the logger.
func (l *LoggerHandler) writeEntry(w ResponseLogger, r *http.Request, t time.Time, d time.Duration) {
	var reqID, user string

	ctx := r.Context()
	if v, ok := ctx.Value(RequestIDKey).(string); ok && v != "" {
		reqID = v
	}
	if v, ok := ctx.Value(UserIDKey).(string); ok && v != "" {
		user = v
	}

	// Remote hostname
	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		addr = r.RemoteAddr
	}

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

	status := w.StatusCode()

	fields := logrus.Fields{
		"request-id":     reqID,
		"remote-address": addr,
		"name":           l.name,
		"user-id":        user,
		"time":           t.Format(time.RFC3339),
		"duration-ns":    d.Nanoseconds(),
		"duration":       d.String(),
		"method":         r.Method,
		"path":           uri,
		"protocol":       r.Proto,
		"status":         status,
		"size":           w.Size(),
		"referer":        r.Referer(),
		"user-agent":     r.UserAgent(),
	}

	for k, v := range w.Fields() {
		fields[k] = v
	}

	switch {
	case status < http.StatusBadRequest:
		l.logger.WithFields(fields).Info()
	case status < http.StatusInternalServerError:
		l.logger.WithFields(fields).Warn()
	default:
		l.logger.WithFields(fields).Error()
	}
}
