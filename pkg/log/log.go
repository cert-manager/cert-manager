package log

import (
	"fmt"
	stdlog "log"
)

// Logger is a generic logging interface
type Logger interface {
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Fatalf(string, ...interface{})
}

// Default returns a default logging implementation
func Default() Logger {
	return &defaultLogger{}
}

// defaultLogger is a wrapper around the stdlib 'log' package
type defaultLogger struct{}

var _ Logger = &defaultLogger{}

func (d *defaultLogger) Printf(str string, args ...interface{}) {
	stdlog.Printf(str, args...)
}

func (d *defaultLogger) Errorf(str string, args ...interface{}) {
	stdlog.Printf(fmt.Sprintf("ERROR: %s", str), args...)
}

func (d *defaultLogger) Fatalf(str string, args ...interface{}) {
	stdlog.Panicf(str, args...)
}
