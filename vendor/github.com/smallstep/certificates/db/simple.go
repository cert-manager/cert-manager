package db

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/pkg/errors"
)

// ErrNotImplemented is an error returned when an operation is Not Implemented.
var ErrNotImplemented = errors.Errorf("not implemented")

// SimpleDB is a barebones implementation of the DB interface. It is NOT an
// in memory implementation of the DB, but rather the bare minimum of
// functionality that the CA requires to operate securely.
type SimpleDB struct {
	usedTokens *sync.Map
}

func newSimpleDB(c *Config) (AuthDB, error) {
	db := &SimpleDB{}
	db.usedTokens = new(sync.Map)
	return db, nil
}

// IsRevoked noop
func (s *SimpleDB) IsRevoked(sn string) (bool, error) {
	return false, nil
}

// Revoke returns a "NotImplemented" error.
func (s *SimpleDB) Revoke(rci *RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// StoreCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreCertificate(crt *x509.Certificate) error {
	return ErrNotImplemented
}

type usedToken struct {
	UsedAt int64  `json:"ua,omitempty"`
	Token  string `json:"tok,omitempty"`
}

// UseToken returns a "NotImplemented" error.
func (s *SimpleDB) UseToken(id, tok string) (bool, error) {
	if _, ok := s.usedTokens.LoadOrStore(id, &usedToken{
		UsedAt: time.Now().Unix(),
		Token:  tok,
	}); ok {
		// Token already exists in DB.
		return false, nil
	}
	// Successfully stored token.
	return true, nil
}

// Shutdown returns nil
func (s *SimpleDB) Shutdown() error {
	return nil
}
