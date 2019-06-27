// +build go1.7

package newrelic

import (
	"context"
	"net/http"

	"github.com/newrelic/go-agent/internal"
)

// NewContext returns a new Context that carries the provided transcation.
func NewContext(ctx context.Context, txn Transaction) context.Context {
	return context.WithValue(ctx, internal.TransactionContextKey, txn)
}

// FromContext returns the Transaction from the context if present, and nil
// otherwise.
func FromContext(ctx context.Context) Transaction {
	h, _ := ctx.Value(internal.TransactionContextKey).(Transaction)
	if nil != h {
		return h
	}
	// If we couldn't find a transaction using
	// internal.TransactionContextKey, try with
	// internal.GinTransactionContextKey.  Unfortunately, gin.Context.Set
	// requires a string key, so we cannot use
	// internal.TransactionContextKey in nrgin.Middleware.  We check for two
	// keys (rather than turning internal.TransactionContextKey into a
	// string key) because context.WithValue will cause golint to complain
	// if used with a string key.
	h, _ = ctx.Value(internal.GinTransactionContextKey).(Transaction)
	return h
}

// RequestWithTransactionContext adds the transaction to the request's context.
func RequestWithTransactionContext(req *http.Request, txn Transaction) *http.Request {
	ctx := req.Context()
	ctx = NewContext(ctx, txn)
	return req.WithContext(ctx)
}

func transactionFromRequestContext(req *http.Request) Transaction {
	var txn Transaction
	if nil != req {
		txn = FromContext(req.Context())
	}
	return txn
}
