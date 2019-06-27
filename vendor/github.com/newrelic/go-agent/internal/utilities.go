package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// JSONString assists in logging JSON:  Based on the formatter used to log
// Context contents, the contents could be marshalled as JSON or just printed
// directly.
type JSONString string

// MarshalJSON returns the JSONString unmodified without any escaping.
func (js JSONString) MarshalJSON() ([]byte, error) {
	if "" == js {
		return []byte("null"), nil
	}
	return []byte(js), nil
}

func removeFirstSegment(name string) string {
	idx := strings.Index(name, "/")
	if -1 == idx {
		return name
	}
	return name[idx+1:]
}

func timeToFloatSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / float64(1000*1000*1000)
}

func timeToFloatMilliseconds(t time.Time) float64 {
	return float64(t.UnixNano()) / float64(1000*1000)
}

// FloatSecondsToDuration turns a float64 in seconds into a time.Duration.
func FloatSecondsToDuration(seconds float64) time.Duration {
	nanos := seconds * 1000 * 1000 * 1000
	return time.Duration(nanos) * time.Nanosecond
}

func absTimeDiff(t1, t2 time.Time) time.Duration {
	if t1.After(t2) {
		return t1.Sub(t2)
	}
	return t2.Sub(t1)
}

// CompactJSONString removes the whitespace from a JSON string.  This function
// will panic if the string provided is not valid JSON.  Thus is must only be
// used in testing code!
func CompactJSONString(js string) string {
	buf := new(bytes.Buffer)
	if err := json.Compact(buf, []byte(js)); err != nil {
		panic(fmt.Errorf("unable to compact JSON: %v", err))
	}
	return buf.String()
}

// GetContentLengthFromHeader gets the content length from a HTTP header, or -1
// if no content length is available.
func GetContentLengthFromHeader(h http.Header) int64 {
	if cl := h.Get("Content-Length"); cl != "" {
		if contentLength, err := strconv.ParseInt(cl, 10, 64); err == nil {
			return contentLength
		}
	}

	return -1
}

// StringLengthByteLimit truncates strings using a byte-limit boundary and
// avoids terminating in the middle of a multibyte character.
func StringLengthByteLimit(str string, byteLimit int) string {
	if len(str) <= byteLimit {
		return str
	}

	limitIndex := 0
	for pos := range str {
		if pos > byteLimit {
			break
		}
		limitIndex = pos
	}
	return str[0:limitIndex]
}

func timeFromUnixMilliseconds(millis uint64) time.Time {
	secs := int64(millis) / 1000
	msecsRemaining := int64(millis) % 1000
	nsecsRemaining := msecsRemaining * (1000 * 1000)
	return time.Unix(secs, nsecsRemaining)
}

// TimeToUnixMilliseconds converts a time into a Unix timestamp in millisecond
// units.
func TimeToUnixMilliseconds(tm time.Time) uint64 {
	return uint64(tm.UnixNano()) / uint64(1000*1000)
}
