package middleware

import (
	"context"

	"github.com/golang/glog"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/client"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
)

func NewLogger(baseCl client.Interface) client.Interface {
	return &Logger{baseCl: baseCl}
}

// Logger is a glog based logging middleware for an ACME client
type Logger struct {
	baseCl client.Interface
}

func (l *Logger) CreateOrder(ctx context.Context, order *acme.Order) (*acme.Order, error) {
	glog.Infof("Calling CreateOrder")
	return l.CreateOrder(ctx, order)
}

func (l *Logger) GetOrder(ctx context.Context, url string) (*acme.Order, error) {
	glog.Infof("Calling GetOrder")
	return l.GetOrder(ctx, url)
}

func (l *Logger) FinalizeOrder(ctx context.Context, finalizeURL string, csr []byte) (der [][]byte, err error) {
	glog.Infof("Calling FinalizeOrder")
	return l.FinalizeOrder(ctx, finalizeURL, csr)
}

func (l *Logger) AcceptChallenge(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	glog.Infof("Calling AcceptChallenge")
	return l.AcceptChallenge(ctx, chal)
}

func (l *Logger) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	glog.Infof("Calling GetChallenge")
	return l.GetChallenge(ctx, url)
}

func (l *Logger) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	glog.Infof("Calling GetAuthorization")
	return l.GetAuthorization(ctx, url)
}

func (l *Logger) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	glog.Infof("Calling WaitAuthorization")
	return l.WaitAuthorization(ctx, url)
}

func (l *Logger) CreateAccount(ctx context.Context, a *acme.Account) (*acme.Account, error) {
	glog.Infof("Calling CreateAccount")
	return l.CreateAccount(ctx, a)
}

func (l *Logger) GetAccount(ctx context.Context) (*acme.Account, error) {
	glog.Infof("Calling GetAccount")
	return l.GetAccount(ctx)
}

func (l *Logger) HTTP01ChallengeResponse(token string) (string, error) {
	glog.Infof("Calling HTTP01ChallengeResponse")
	return l.HTTP01ChallengeResponse(token)
}

func (l *Logger) DNS01ChallengeRecord(token string) (string, error) {
	glog.Infof("Calling DNS01ChallengeRecord")
	return l.DNS01ChallengeRecord(token)
}
