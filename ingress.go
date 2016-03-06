package main

import (
	"fmt"
	"strings"
	"log"
	"sort"

	"k8s.io/kubernetes/pkg/apis/extensions"
)

const annotationIngressEnabled = "kubernetes.io/lego-enabled"
const annotationIngressHash = "kubernetes.io/lego-domain-hash"

type Ingress struct {
	extensions.Ingress
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

	for _,rule := range i.Spec.Rules{
		domainsMap[rule.Host] = true
	}

	domainsList := []string{}
	for k := range domainsMap {
		domainsList = append(domainsList, k)
	}

	sort.Strings(domainsList)

	return domainsList
}

func (i *Ingress) Process(kl *KubeLego) {
	domains := i.Domains()

	log.Printf("%s has the domains %v", i.String(), domains)

	certificates, err := kl.LegoClient.ObtainCertificate(domains, true, nil)
	if err != nil {
		log.Print(err)
	}

	log.Printf("%+v\n", certificates)

}

