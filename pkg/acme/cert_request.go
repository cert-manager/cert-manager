package acme

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"github.com/cenk/backoff"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
	"time"
)

func (a *Acme) ensureAcmeClient() error {

	// get existing user or create new one
	client, accountURI, err := a.getUser()
	if err != nil {
		client, account, err := a.createUser()
		if err != nil {
			return err
		}
		a.acmeAccount = account
		a.acmeClient = client
		return nil
	}

	account, err := a.validateUser(client, accountURI)
	if err != nil {
		a.Log().Fatalf("fatal error verifying existing user: %s", err)
	}
	a.acmeAccount = account
	a.acmeClient = client
	return nil
}

func (a *Acme) testReachablilty(domain string) error {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = domain
	url.Path = kubelego.AcmeHttpSelfTest

	a.Log().WithField("domain", domain).Debugf("testing reachability of %s", url.String())
	response, err := http.Get(url.String())
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("wrong status code '%d'", response.StatusCode)
	}

	defer response.Body.Close()
	idReceived, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.New("unable to read body")
	}

	if string(idReceived) != a.id {
		if err != nil {
			return fmt.Errorf("received id (%s) did not match expected (%s)", idReceived, a.id)
		}
	}
	return nil
}

func (a *Acme) verifyDomain(domain string) (auth *acme.Authorization, err error) {
	err = a.testReachablilty(domain)
	if err != nil {
		return nil, fmt.Errorf("reachability test failed: %s", err)
	}

	auth, err = a.acmeClient.Authorize(context.Background(), domain)
	if err != nil {
		return nil, fmt.Errorf("getting authorization failed: %s", err)
	}

	var challenge *acme.Challenge
	for _, ch := range auth.Challenges {
		if ch.Type == "http-01" {
			challenge = ch
			break
		}
	}

	if challenge == nil {
		return nil, fmt.Errorf("no http-01 challenge was offered")
	}

	token := challenge.Token
	key, err := a.acmeClient.HTTP01ChallengeResponse(token)
	if err != nil {
		return nil, fmt.Errorf("error generating http-01 response: %s", err)
	}

	a.Present(domain, token, key)

	challenge, err = a.acmeClient.Accept(context.Background(), challenge)
	if err != nil {
		return nil, fmt.Errorf("requesting challenge failed: %s", err)
	}

	auth, err = a.acmeClient.WaitAuthorization(context.Background(), challenge.URI)
	if err != nil {
		return nil, fmt.Errorf("waiting for authorization failed: %s", err)
	}
	return auth, nil
}

func (a *Acme) ObtainCertificate(domains []string) (data map[string][]byte, err error) {
	err = a.ensureAcmeClient()
	if err != nil {
		return data, err
	}

	var wg sync.WaitGroup
	results := make([]error, len(domains))

	// authorize all domains in parallel
	for pos, domain := range domains {
		wg.Add(1)
		go func(pos int, domain string) {
			defer wg.Done()
			log := a.Log().WithField("domain", domain)

			op := func() error {
				auth, err := a.verifyDomain(domain)
				if err != nil {
					log.Debugf("error while authorizing: %s", err)
					return err
				}
				log.Debugf("got authorization: %+v", auth)
				return nil
			}

			b := backoff.NewExponentialBackOff()
			b.MaxElapsedTime = time.Duration(time.Second * 60)

			err = backoff.Retry(op, b)
			if err != nil {
				log.Warnf("authorization failed after %s: %s", b.MaxElapsedTime, err)
			} else {
				log.Infof("authorization successful")
			}
			results[pos] = err

		}(pos, domain)
	}

	// wait for all authorizations to complete
	wg.Wait()

	// check if all the domains are authorized correctly
	successfulDomains := []string{}
	failedDomains := []string{}
	for pos, domain := range domains {
		res := results[pos]
		if res == nil {
			successfulDomains = append(successfulDomains, domain)
		} else {
			failedDomains = append(failedDomains, domain)
		}
	}

	if len(successfulDomains) == 0 {
		return data, fmt.Errorf("no domain could be authorized successfully")
	}

	if len(failedDomains) > 0 {
		a.Log().WithField("failed_domains", failedDomains).Warnf("authorization failed for some domains")
	}
	// TODO: Mark failed domains as failed in ingress

	domains = successfulDomains

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domains[0],
		},
	}

	if len(domains) > 1 {
		template.DNSNames = domains
	}

	privateKeyPem, privateKey, err := a.generatePrivateKey()
	if err != nil {
		return data, fmt.Errorf("error generating private key: %s", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return data, fmt.Errorf("error certificate request: %s", err)
	}

	certSlice, certUrl, err := a.acmeClient.CreateCert(
		context.Background(),
		csr,
		0,
		true,
	)
	if err != nil {
		return data, fmt.Errorf("error getting certificate: %s", err)
	}

	certBuffer := bytes.NewBuffer([]byte{})
	for _, cert := range certSlice {
		pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	a.Log().Infof("successfully got certificate: domains=%+v url=%s", domains, certUrl)
	a.Log().Debugf("certificate pem data:\n%s", certBuffer.String())

	data = map[string][]byte{
		kubelego.TLSCertKey:       certBuffer.Bytes(),
		kubelego.TLSPrivateKeyKey: privateKeyPem,
	}

	return
}

func (a *Acme) CleanUp(domain, token, _ string) error {
	a.challengesMutex.Lock()
	if _, ok := a.challengesTokenToKey[token]; ok {
		delete(a.challengesTokenToKey, token)
	}
	if _, ok := a.challengesHostToToken[domain]; ok {
		delete(a.challengesHostToToken, domain)
	}
	a.challengesMutex.Unlock()
	return nil
}

func (a *Acme) Present(domain, token, key string) error {
	a.challengesMutex.Lock()
	a.challengesHostToToken[domain] = token
	a.challengesTokenToKey[token] = key
	a.challengesMutex.Unlock()
	return nil
}
