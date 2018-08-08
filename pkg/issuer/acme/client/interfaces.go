package client

import (
	"context"

	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

type Interface interface {
	CreateOrder(ctx context.Context, order *acme.Order) (*acme.Order, error)
	GetOrder(ctx context.Context, url string) (*acme.Order, error)
	GetCertificate(ctx context.Context, url string) ([][]byte, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte) (der [][]byte, err error)
	AcceptChallenge(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	CreateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error)
	GetAccount(ctx context.Context) (*acme.Account, error)
	HTTP01ChallengeResponse(token string) (string, error)
	DNS01ChallengeRecord(token string) (string, error)
}

var _ Interface = &acme.Client{}
