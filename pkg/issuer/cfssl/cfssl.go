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

package cfssl

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	cfsslclient "github.com/cloudflare/cfssl/api/client"
	cfsslauth "github.com/cloudflare/cfssl/auth"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// CFSSL allows communicating with a remote cfssl based certificate authority.
// A secret resource is used to store the authkey that is used to make authenticated requests to the remote CA server.
type CFSSL struct {
	*controller.Context
	issuer        v1alpha1.GenericIssuer
	secretsLister corelisters.SecretLister

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string

	client cfsslclient.Remote
}

// signRequest defines the body of a request to send to a remote cfssl ca server
type signRequest struct {
	Label              string `json:"label,omitempty"`
	Profile            string `json:"profile,omitempty"`
	CertificateRequest string `json:"certificate_request"`
}

// NewCFSSL initializes a new CFSSL struct and returns a pointer to it
func NewCFSSL(ctx *controller.Context, issuer v1alpha1.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()
	resourceNamespace := ctx.IssuerOptions.ResourceNamespace(issuer)

	client, err := cfsslClient(issuer, secretsLister, resourceNamespace)
	if err != nil {
		ctx.Recorder.Eventf(issuer, corev1.EventTypeWarning, reasonErrorInitIssuer, "failed to initialise issuer: %v", err)
		return nil, err
	}

	return &CFSSL{
		Context:           ctx,
		issuer:            issuer,
		secretsLister:     secretsLister,
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
		client:            client,
	}, nil
}

func cfsslClient(issuer v1alpha1.GenericIssuer, secretsLister corelisters.SecretLister, resourceNamespace string) (cfsslclient.Remote, error) {
	spec := issuer.GetSpec().CFSSL
	if spec == nil {
		return nil, fmt.Errorf("unexpected error: CFSSL issuer spec should not be nil")
	}

	if spec.AuthKey == nil {
		return cfsslclient.NewServer(spec.Server), nil
	}

	secret, err := secretsLister.Secrets(resourceNamespace).Get(spec.AuthKey.Name)
	if err != nil {
		return nil, fmt.Errorf("error loading cfssl issuer authkey: %v", err)
	}

	keyBytes, ok := secret.Data[spec.AuthKey.Key]
	if !ok {
		return nil, fmt.Errorf("no data for %q in secret '%s/%s'", spec.AuthKey.Key, spec.AuthKey.Name, resourceNamespace)
	}

	var additionalData []byte

	provider, err := cfsslauth.New(string(keyBytes), additionalData)
	if err != nil {
		return nil, fmt.Errorf("error creating auth provider: %v", err)
	}

	var tlsConfig *tls.Config

	if len(spec.CABundle) > 0 {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(spec.CABundle); !ok {
			return nil, fmt.Errorf("error loading CFSSL CA bundle")
		}

		tlsConfig = &tls.Config{RootCAs: caCertPool}
	}

	return cfsslclient.NewAuthServer(spec.Server, tlsConfig, provider), nil
}

// Register CFSSL Issuer with the issuer factory
func init() {
	issuer.RegisterIssuer(apiutil.IssuerCFSSL, NewCFSSL)
}
