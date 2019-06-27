package internal

type contextKeyType struct{}

var (
	// TransactionContextKey is the key used for newrelic.FromContext and
	// newrelic.NewContext.
	TransactionContextKey = contextKeyType(struct{}{})

	// GinTransactionContextKey is used as the context key in
	// nrgin.Middleware and nrgin.Transaction.  Unfortunately, Gin requires
	// a string context key. We use two different context keys (and check
	// both in nrgin.Transaction and newrelic.FromContext) rather than use a
	// single string key because context.WithValue will fail golint if used
	// with a string key.
	GinTransactionContextKey = "newRelicTransaction"
)
