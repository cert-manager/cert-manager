package errors

import "fmt"

type invalidDataError struct{ error }

func NewInvalidData(str string, obj ...interface{}) error {
	return &invalidDataError{error: fmt.Errorf(str, obj...)}
}

func IsInvalidData(err error) bool {
	if _, ok := err.(*invalidDataError); !ok {
		return false
	}
	return true
}
