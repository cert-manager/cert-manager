package logging

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// defaultTraceIdHeader is the default header used as a trace id.
const defaultTraceIDHeader = "X-Smallstep-Id"

// ErrorKey defines the key used to log errors.
var ErrorKey = logrus.ErrorKey

// Logger is an alias of logrus.Logger.
type Logger struct {
	*logrus.Logger
	name        string
	traceHeader string
}

// loggerConfig represents the configuration options for the logger.
type loggerConfig struct {
	Format      string `json:"format"`
	TraceHeader string `json:"traceHeader"`
}

// New initializes the logger with the given options.
func New(name string, raw json.RawMessage) (*Logger, error) {
	var config loggerConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling logging attribute")
	}

	var formatter logrus.Formatter
	switch strings.ToLower(config.Format) {
	case "", "text":
	case "json":
		formatter = new(logrus.JSONFormatter)
	case "common":
		formatter = new(CommonLogFormat)
	default:
		return nil, errors.Errorf("unsupported logger.format '%s'", config.Format)
	}

	logger := &Logger{
		Logger:      logrus.New(),
		name:        name,
		traceHeader: config.TraceHeader,
	}
	if formatter != nil {
		logger.Formatter = formatter
	}
	return logger, nil
}

// GetImpl returns the real implementation of the logger.
func (l *Logger) GetImpl() *logrus.Logger {
	return l.Logger
}

// GetTraceHeader returns the trace header configured
func (l *Logger) GetTraceHeader() string {
	if l.traceHeader == "" {
		return defaultTraceIDHeader
	}
	return l.traceHeader
}

// Middleware returns the logger middleware that will trace the request of the
// given handler.
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return NewLoggerHandler(l.name, l, next)
}
