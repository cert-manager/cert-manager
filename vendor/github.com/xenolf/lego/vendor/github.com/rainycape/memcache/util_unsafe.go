// +build !appengine

package memcache

import (
	"unsafe"
)

func stobs(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}
