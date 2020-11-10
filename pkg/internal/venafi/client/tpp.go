/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	venafidefaults "github.com/jetstack/cert-manager/pkg/internal/venafi/defaults"
)

const (
	tppUsernameKey     = "username"
	tppPasswordKey     = "password"
	tppAccessTokenKey  = "access-token"
	tppExpiresKey      = "expires"
	tppRefreshTokenKey = "refresh-token"
)

func extractAuth(data map[string][]byte) (auth *endpoint.Authentication, err error) {
	username, usernameFound := data[tppUsernameKey]
	password, passwordFound := data[tppPasswordKey]
	someUsernamePasswordFound := usernameFound || passwordFound

	accessToken, accessTokenFound := data[tppAccessTokenKey]
	expiryBytes, expiryFound := data[tppExpiresKey]
	_, refreshTokenFound := data[tppRefreshTokenKey]
	someOauthFound := accessTokenFound || expiryFound || refreshTokenFound

	expirySeconds, expiryParseError := strconv.Atoi(string(expiryBytes))
	expiry := time.Unix(int64(expirySeconds), 0)

	switch {
	case someUsernamePasswordFound:
		switch {
		case someOauthFound:
			err = fmt.Errorf("%w: please supply username-password OR oauth credentials, not both", ErrInvalidCredentials)
		case !usernameFound:
			err = fmt.Errorf("%w: missing username", ErrInvalidCredentials)
		case !passwordFound:
			err = fmt.Errorf("%w: missing password", ErrInvalidCredentials)
		default:
			auth = &endpoint.Authentication{
				User:     string(username),
				Password: string(password),
			}
		}
	case someOauthFound:
		switch {
		case !accessTokenFound:
			err = fmt.Errorf("%w: missing access-token", ErrAccessTokenMissing)
		case !expiryFound:
			err = fmt.Errorf("%w: missing expiry", ErrInvalidCredentials)
		case expiryParseError != nil:
			err = fmt.Errorf("%w: unable to parse access-token expiry time: %v", ErrInvalidCredentials, expiryParseError)
		case expiry.Before(time.Now()):
			err = fmt.Errorf("%w: %s", ErrAccessTokenExpired, expiry.String())
		default:
			auth = &endpoint.Authentication{
				AccessToken: string(accessToken),
			}
		}
	default:
		err = fmt.Errorf("%w: no credentials found", ErrInvalidCredentials)
	}
	return auth, err
}

type tppAuthenticator struct {
	store CredentialStore
	tpp   *tpp.Connector
}

var _ authenticator = &tppAuthenticator{}

func (o *tppAuthenticator) Authenticate() error {
	data, err := o.store.Load(context.TODO())
	if err != nil {
		return err
	}
	auth, err := extractAuth(data)
	if err != nil {
		return err
	}
	if err := o.tpp.Authenticate(auth); err != nil {
		return err
	}
	return nil
}

func (o *tppAuthenticator) RotateCredentials() error {
	data, err := o.store.Load(context.TODO())
	if err != nil {
		return err
	}
	refreshToken, refreshTokenFound := data[tppRefreshTokenKey]
	if !refreshTokenFound {
		return errors.New("refresh-token not found")
	}

	resp, err := o.tpp.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: string(refreshToken),
		ClientId:     venafidefaults.DefaultClientID,
	})
	if err != nil {
		return fmt.Errorf("error refreshing access token: %v", err)
	}
	data = map[string][]byte{
		tppAccessTokenKey:  []byte(resp.Access_token),
		tppExpiresKey:      []byte(strconv.Itoa(resp.Expires)),
		tppRefreshTokenKey: []byte(resp.Refresh_token),
	}
	if err := o.store.Save(context.TODO(), data); err != nil {
		return fmt.Errorf("error saving credentials: %v", err)
	}
	auth, err := extractAuth(data)
	if err != nil {
		return err
	}
	if err := o.tpp.Authenticate(auth); err != nil {
		return err
	}
	return nil
}

func newTPPConnector(cfg *cmapi.VenafiTPP, zone string) (*tpp.Connector, error) {
	var connectionTrustBundle *x509.CertPool
	if len(cfg.CABundle) > 0 {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM(cfg.CABundle) {
			return nil, fmt.Errorf("%w: failed to parse PEM trust bundle", ErrInvalidConfiguration)
		}
	}
	return tpp.NewConnector(cfg.URL, zone, false, connectionTrustBundle)
}

func newTPP(cfg *cmapi.VenafiTPP, zone string, credentialStore CredentialStore) (*Venafi, error) {
	connector, err := newTPPConnector(cfg, zone)
	if err != nil {
		return nil, err
	}
	return &Venafi{
		vcertClient: connector,
		authenticator: &tppAuthenticator{
			store: credentialStore,
			tpp:   connector,
		},
	}, nil
}
