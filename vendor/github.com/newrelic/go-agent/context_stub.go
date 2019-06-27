// +build !go1.7

package newrelic

import "net/http"

// RequestWithTransactionContext adds the transaction to the request's context.
func RequestWithTransactionContext(req *http.Request, txn Transaction) *http.Request {
	return req
}

func transactionFromRequestContext(req *http.Request) Transaction {
	return nil
}
