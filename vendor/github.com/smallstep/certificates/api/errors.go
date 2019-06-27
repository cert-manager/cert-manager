package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/logging"
)

// StatusCoder interface is used by errors that returns the HTTP response code.
type StatusCoder interface {
	StatusCode() int
}

// StackTracer must be by those errors that return an stack trace.
type StackTracer interface {
	StackTrace() errors.StackTrace
}

// Error represents the CA API errors.
type Error struct {
	Status int
	Err    error
}

// ErrorResponse represents an error in JSON format.
type ErrorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// Cause implements the errors.Causer interface and returns the original error.
func (e *Error) Cause() error {
	return e.Err
}

// Error implements the error interface and returns the error string.
func (e *Error) Error() string {
	return e.Err.Error()
}

// StatusCode implements the StatusCoder interface and returns the HTTP response
// code.
func (e *Error) StatusCode() int {
	return e.Status
}

// MarshalJSON implements json.Marshaller interface for the Error struct.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ErrorResponse{Status: e.Status, Message: http.StatusText(e.Status)})
}

// UnmarshalJSON implements json.Unmarshaler interface for the Error struct.
func (e *Error) UnmarshalJSON(data []byte) error {
	var er ErrorResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return err
	}
	e.Status = er.Status
	e.Err = fmt.Errorf(er.Message)
	return nil
}

// NewError returns a new Error. If the given error implements the StatusCoder
// interface we will ignore the given status.
func NewError(status int, err error) error {
	if sc, ok := err.(StatusCoder); ok {
		return &Error{Status: sc.StatusCode(), Err: err}
	}
	cause := errors.Cause(err)
	if sc, ok := cause.(StatusCoder); ok {
		return &Error{Status: sc.StatusCode(), Err: err}
	}
	return &Error{Status: status, Err: err}
}

// InternalServerError returns a 500 error with the given error.
func InternalServerError(err error) error {
	return NewError(http.StatusInternalServerError, err)
}

// NotImplemented returns a 500 error with the given error.
func NotImplemented(err error) error {
	return NewError(http.StatusNotImplemented, err)
}

// BadRequest returns an 400 error with the given error.
func BadRequest(err error) error {
	return NewError(http.StatusBadRequest, err)
}

// Unauthorized returns an 401 error with the given error.
func Unauthorized(err error) error {
	return NewError(http.StatusUnauthorized, err)
}

// Forbidden returns an 403 error with the given error.
func Forbidden(err error) error {
	return NewError(http.StatusForbidden, err)
}

// NotFound returns an 404 error with the given error.
func NotFound(err error) error {
	return NewError(http.StatusNotFound, err)
}

// WriteError writes to w a JSON representation of the given error.
func WriteError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	cause := errors.Cause(err)
	if sc, ok := err.(StatusCoder); ok {
		w.WriteHeader(sc.StatusCode())
	} else {
		if sc, ok := cause.(StatusCoder); ok {
			w.WriteHeader(sc.StatusCode())
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	// Write errors in the response writer
	if rl, ok := w.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"error": err,
		})
		if os.Getenv("STEPDEBUG") == "1" {
			if e, ok := err.(StackTracer); ok {
				rl.WithFields(map[string]interface{}{
					"stack-trace": fmt.Sprintf("%+v", e),
				})
			} else {
				if e, ok := cause.(StackTracer); ok {
					rl.WithFields(map[string]interface{}{
						"stack-trace": fmt.Sprintf("%+v", e),
					})
				}
			}
		}
	}

	if err := json.NewEncoder(w).Encode(err); err != nil {
		LogError(w, err)
	}
}
