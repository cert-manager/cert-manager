/*
Copyright 2024 The cert-manager Authors.

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

package dns

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func buildHTTPClientFromCABundle(caBundle []byte) (*http.Client, error) {
	if len(caBundle) == 0 {
		return nil, nil
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caBundle); !ok {
		return nil, fmt.Errorf("failed to parse caBundle: no valid certificates found in PEM data")
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}, nil
}

func (s *Solver) resolveCABundle(ch *cmacme.Challenge) ([]byte, error) {
	if ch.Spec.Solver.DNS01 != nil &&
		ch.Spec.Solver.DNS01.AcmeDNS != nil &&
		len(ch.Spec.Solver.DNS01.AcmeDNS.CABundle) > 0 {
		return ch.Spec.Solver.DNS01.AcmeDNS.CABundle, nil
	}

	if ch.Spec.IssuerRef.Kind == "ClusterIssuer" {
		if s.clusterIssuerLister == nil {
			return nil, fmt.Errorf("cannot resolve ClusterIssuer %q: solver is running in namespaced mode", ch.Spec.IssuerRef.Name)
		}
		issuer, err := s.clusterIssuerLister.Get(ch.Spec.IssuerRef.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get %s %q: %w", ch.Spec.IssuerRef.Kind, ch.Spec.IssuerRef.Name, err)
		}
		if issuer.GetSpec().ACME != nil && len(issuer.GetSpec().ACME.CABundle) > 0 {
			return issuer.GetSpec().ACME.CABundle, nil
		}
		return nil, nil
	}

	if s.issuerLister == nil {
		return nil, nil
	}

	issuer, err := s.issuerLister.Issuers(ch.Namespace).Get(ch.Spec.IssuerRef.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s %q: %w", ch.Spec.IssuerRef.Kind, ch.Spec.IssuerRef.Name, err)
	}
	if issuer.GetSpec().ACME != nil && len(issuer.GetSpec().ACME.CABundle) > 0 {
		return issuer.GetSpec().ACME.CABundle, nil
	}
	return nil, nil
}
