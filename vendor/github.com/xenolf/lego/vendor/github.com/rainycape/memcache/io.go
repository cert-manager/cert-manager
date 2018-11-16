package memcache

import (
	"io"
)

// readAtLeast is an optimized version of io.ReadAtLeast,
// which omits some checks that don't need to be performed
// when called from Read() in this package.
func readAtLeast(r io.Reader, buf []byte, min int) error {
	var n int
	var err error
	// Most common case, we get all the bytes in one read
	if n, err = r.Read(buf); n == min {
		return nil
	}
	if err != nil {
		return err
	}
	// Fall back to looping
	var nn int
	for n < min {
		nn, err = r.Read(buf[n:])
		if err != nil {
			if err == io.EOF && n > 0 {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
		n += nn
	}
	return nil
}
