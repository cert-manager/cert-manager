package sysinfo

import (
	"errors"
)

var (
	// ErrFeatureUnsupported indicates unsupported platform.
	ErrFeatureUnsupported = errors.New("That feature is not supported on this platform")
)
