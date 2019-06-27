package logging

import (
	"context"
	"net/http"

	"github.com/rs/xid"
)

type key int

const (
	// RequestIDKey is the context key that should store the request identifier.
	RequestIDKey key = iota
	// UserIDKey is the context key that should store the user identifier.
	UserIDKey
)

// NewRequestID creates a new request id using github.com/rs/xid.
func NewRequestID() string {
	return xid.New().String()
}

// RequestID returns a new middleware that gets the given header and sets it
// in the context so it can be written in the logger. If the header does not
// exists or it's the empty string, it uses github.com/rs/xid to create a new
// one.
func RequestID(headerName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, req *http.Request) {
			requestID := req.Header.Get(headerName)
			if requestID == "" {
				requestID = NewRequestID()
				req.Header.Set(headerName, requestID)
			}

			ctx := WithRequestID(req.Context(), requestID)
			next.ServeHTTP(w, req.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// WithRequestID returns a new context with the given requestID added to the
// context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID returns the request id from the context if it exists.
func GetRequestID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(RequestIDKey).(string)
	return v, ok
}

// WithUserID decodes the token, extracts the user from the payload and stores
// it in the context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// GetUserID returns the request id from the context if it exists.
func GetUserID(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(UserIDKey).(string)
	return v, ok
}
