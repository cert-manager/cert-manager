package vcs

import (
	"errors"
	"testing"
)

func TestNewRemoteError(t *testing.T) {
	base := errors.New("Foo error")
	out := "This is a test"
	msg := "remote error msg"

	e := NewRemoteError(msg, base, out)

	switch e.(type) {
	case *RemoteError:
		// This is the right error type
	default:
		t.Error("Wrong error type returned from NewRemoteError")
	}
}

func TestNewLocalError(t *testing.T) {
	base := errors.New("Foo error")
	out := "This is a test"
	msg := "local error msg"

	e := NewLocalError(msg, base, out)

	switch e.(type) {
	case *LocalError:
		// This is the right error type
	default:
		t.Error("Wrong error type returned from NewLocalError")
	}
}
