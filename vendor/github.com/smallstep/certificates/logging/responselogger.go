package logging

import (
	"bufio"
	"net"
	"net/http"
)

// ResponseLogger defines an interface that a responseWrite can implement to
// support the capture of the status code, the number of bytes written and
// extra log entry fields.
type ResponseLogger interface {
	http.ResponseWriter
	Size() int
	StatusCode() int
	Fields() map[string]interface{}
	WithFields(map[string]interface{})
}

// NewResponseLogger wraps the given response writer with methods to capture
// the status code, the number of bytes written, and methods to add new log
// entries. It won't wrap the response writer if it's already a
// ResponseLogger.
func NewResponseLogger(w http.ResponseWriter) ResponseLogger {
	if rw, ok := w.(ResponseLogger); ok {
		return rw
	}
	return wrapLogger(w)
}

func wrapLogger(w http.ResponseWriter) (rw ResponseLogger) {
	rw = &rwDefault{w, 200, 0, nil}
	if c, ok := w.(http.CloseNotifier); ok {
		rw = &rwCloseNotifier{rw, c}
	}
	if f, ok := w.(http.Flusher); ok {
		rw = &rwFlusher{rw, f}
	}
	if h, ok := w.(http.Hijacker); ok {
		rw = &rwHijacker{rw, h}
	}
	if p, ok := w.(http.Pusher); ok {
		rw = &rwPusher{rw, p}
	}
	return
}

type rwDefault struct {
	http.ResponseWriter
	code   int
	size   int
	fields map[string]interface{}
}

func (r *rwDefault) Header() http.Header {
	return r.ResponseWriter.Header()
}

func (r *rwDefault) Write(p []byte) (n int, err error) {
	n, err = r.ResponseWriter.Write(p)
	r.size += n
	return
}

func (r *rwDefault) WriteHeader(code int) {
	r.ResponseWriter.WriteHeader(code)
	r.code = code
}

func (r *rwDefault) Size() int {
	return r.size
}

func (r *rwDefault) StatusCode() int {
	return r.code
}

func (r *rwDefault) Fields() map[string]interface{} {
	return r.fields
}

func (r *rwDefault) WithFields(fields map[string]interface{}) {
	if r.fields == nil {
		r.fields = make(map[string]interface{}, len(fields))
	}
	for k, v := range fields {
		r.fields[k] = v
	}
}

type rwCloseNotifier struct {
	ResponseLogger
	c http.CloseNotifier
}

func (r *rwCloseNotifier) CloseNotify() <-chan bool {
	return r.CloseNotify()
}

type rwFlusher struct {
	ResponseLogger
	f http.Flusher
}

func (r *rwFlusher) Flush() {
	r.f.Flush()
}

type rwHijacker struct {
	ResponseLogger
	h http.Hijacker
}

func (r *rwHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.h.Hijack()
}

type rwPusher struct {
	ResponseLogger
	p http.Pusher
}

func (rw *rwPusher) Push(target string, opts *http.PushOptions) error {
	return rw.p.Push(target, opts)
}
