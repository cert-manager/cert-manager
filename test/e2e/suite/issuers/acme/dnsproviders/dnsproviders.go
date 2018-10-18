// Package dnsproviders contains addons that create DNS provider credentials
// in the target test environment.
// In most cases, those credentials are access via the CLI flags passed to the
// test suite.
package dnsproviders

import "fmt"

var (
	ErrNoCredentials = fmt.Errorf("no credentials provided for provider")
)
