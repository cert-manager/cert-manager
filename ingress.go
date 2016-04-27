package main

import (
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"

	"github.com/xenolf/lego/acme"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

const annotationIngressEnabled = "kubernetes.io/lego-enabled"
const annotationIngressExpiryDatetime = "kubernetes.io/expiry-datetime"

type Ingress struct {
	extensions.Ingress
	KubeLego *KubeLego
}

func (i *Ingress) Ignore() bool {
	if val, ok := i.Annotations[annotationIngressEnabled]; ok {
		if strings.ToLower(val) == "true" {
			return false
		}
	}
	return true
}

func (i *Ingress) String() string {
	return fmt.Sprintf(
		"<Ingress '%s/%s'>",
		i.Namespace,
		i.Name,
	)
}

// returns ordered list of domains (no duplicates)
func (i *Ingress) Domains() []string {
	domainsMap := make(map[string]bool)

	for _, rule := range i.Spec.Rules {
		domainsMap[rule.Host] = true
	}

	domainsList := []string{}
	for k := range domainsMap {
		domainsList = append(domainsList, k)
	}

	sort.Strings(domainsList)

	return domainsList
}

// returns ordered list of tls domains
// * only first tls specification is used,
// * no duplicates alllowed
func (i *Ingress) TlsDomains() []string {
	for _, tls := range i.Spec.TLS {
		return tls.Hosts
		break
	}
	return []string{}
}

func (i *Ingress) EnsureChallengeEndpoint() error {

	hasChanged := false

	// loop through domains
	for _, rule := range i.Spec.Rules {

		hasChallenge := false

		// ensure there is a acme challenge endpoint
		for _, path := range rule.IngressRuleValue.HTTP.Paths {
			if path.Path == acmeHttpChallengePath {
				hasChallenge = true
				break
			}
		}

		if !hasChallenge {
			rule.IngressRuleValue.HTTP.Paths = append(
				rule.IngressRuleValue.HTTP.Paths,
				extensions.HTTPIngressPath{
					Path: acmeHttpChallengePath,
					Backend: extensions.IngressBackend{
						ServiceName: i.KubeLego.LegoServiceName,
						ServicePort: i.KubeLego.LegoHTTPPort,
					},
				},
			)

			hasChanged = true
		}

	}

	if hasChanged {
		log.Printf("Updating %s with acme http challenge endpoints", i.String())
		ingClient := i.KubeLego.KubeClient.Extensions().Ingress(i.Namespace)
		_, err := ingClient.Update(&i.Ingress)
		return err
	}

	return nil

}

func (i *Ingress) RequestCert() error {

	// update challenge endpoints
	err := i.EnsureChallengeEndpoint()
	if err != nil {
		return err
	}

	// request full bundle
	bundle := true

	// domains to certify
	domains := i.Domains()

	certificates, errs := i.KubeLego.LegoClient.ObtainCertificate(domains, bundle, nil)
	if len(errs) != 0 {
		log.Print(errs)
	}

	return i.StoreCert(&certificates, domains)
}

func (i *Ingress) SecretName() string {
	return fmt.Sprintf("%s-tls", i.ObjectMeta.Name)
}

func (i *Ingress) StoreCert(certs *acme.CertificateResource, domains []string) error {

	// get secret if exists
	updateSecret := true
	secret, err := i.KubeLego.GetSecret(i.SecretName(), i.Namespace)
	if err != nil {
		updateSecret = false
		secret = &api.Secret{
			ObjectMeta: api.ObjectMeta{
				Name:      i.SecretName(),
				Namespace: i.Namespace,
			},
			Type: api.SecretTypeTLS,
		}
	}

	secret.Data = make(map[string][]byte)
	secret.Data[api.TLSPrivateKeyKey] = certs.PrivateKey
	secret.Data[api.TLSCertKey] = certs.Certificate

	if updateSecret {
		_, err = i.KubeLego.UpdateSecret(
			i.Namespace,
			secret,
		)

	} else {
		_, err = i.KubeLego.CreateSecret(
			i.Namespace,
			secret,
		)

	}
	if err != nil {
		return err
	}

	// update ingress
	i.Spec.TLS = []extensions.IngressTLS{
		extensions.IngressTLS{
			Hosts:      domains,
			SecretName: i.SecretName(),
		},
	}

	// retrieve expiry date from cert
	expiryDate, err := pemExpiryDate(certs.Certificate)
	if err != nil {
		return err
	}

	expiryDateBytes, err := expiryDate.MarshalText()
	if err != nil {
		return err
	}

	i.Annotations[annotationIngressExpiryDatetime] = string(expiryDateBytes)
	ingClient := i.KubeLego.KubeClient.Extensions().Ingress(i.Namespace)
	_, err = ingClient.Update(&i.Ingress)

	return err
}

func (i *Ingress) Process() {
	domains := i.Domains()
	tlsDomains := i.TlsDomains()

	if !reflect.DeepEqual(domains, tlsDomains) {
		log.Printf(
			"%s needs certificate update. current tls domains: %v, required domains: %v",
			i.String(),
			tlsDomains,
			domains,
		)
		err := i.RequestCert()
		log.Printf("Error during processing certificate request for %s: %s", i.String(), err)

	}

}
