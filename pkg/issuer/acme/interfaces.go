package acme

import (
	"context"
	"time"

	"golang.org/x/crypto/acme"
)

type client interface {
	CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	HTTP01ChallengeResponse(token string) (string, error)
	DNS01ChallengeRecord(token string) (string, error)
	Authorize(ctx context.Context, domain string) (*acme.Authorization, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
}
