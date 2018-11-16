// Package webroot implements a HTTP provider for solving the HTTP-01 challenge using web server's root path.
package webroot

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/xenolf/lego/acme"
)

// HTTPProvider implements ChallengeProvider for `http-01` challenge
type HTTPProvider struct {
	path string
}

// NewHTTPProvider returns a HTTPProvider instance with a configured webroot path
func NewHTTPProvider(path string) (*HTTPProvider, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("webroot path does not exist")
	}

	return &HTTPProvider{path: path}, nil
}

// Present makes the token available at `HTTP01ChallengePath(token)` by creating a file in the given webroot path
func (w *HTTPProvider) Present(domain, token, keyAuth string) error {
	var err error

	challengeFilePath := filepath.Join(w.path, acme.HTTP01ChallengePath(token))
	err = os.MkdirAll(filepath.Dir(challengeFilePath), 0755)
	if err != nil {
		return fmt.Errorf("could not create required directories in webroot for HTTP challenge -> %v", err)
	}

	err = ioutil.WriteFile(challengeFilePath, []byte(keyAuth), 0644)
	if err != nil {
		return fmt.Errorf("could not write file in webroot for HTTP challenge -> %v", err)
	}

	return nil
}

// CleanUp removes the file created for the challenge
func (w *HTTPProvider) CleanUp(domain, token, keyAuth string) error {
	err := os.Remove(filepath.Join(w.path, acme.HTTP01ChallengePath(token)))
	if err != nil {
		return fmt.Errorf("could not remove file in webroot after HTTP challenge -> %v", err)
	}

	return nil
}
