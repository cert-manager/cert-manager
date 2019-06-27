package authority

import (
	"net/http"
)

type context map[string]interface{}

// Error implements the api.Error interface and adds context to error messages.
type apiError struct {
	err     error
	code    int
	context context
}

// Cause implements the errors.Causer interface and returns the original error.
func (e *apiError) Cause() error {
	return e.err
}

// Error returns an error message with additional context.
func (e *apiError) Error() string {
	ret := e.err.Error()

	/*
		if len(e.context) > 0 {
			ret += "\n\nContext:"
			for k, v := range e.context {
				ret += fmt.Sprintf("\n    %s: %v", k, v)
			}
		}
	*/
	return ret
}

// StatusCode returns an http status code indicating the type and severity of
// the error.
func (e *apiError) StatusCode() int {
	if e.code == 0 {
		return http.StatusInternalServerError
	}
	return e.code
}
