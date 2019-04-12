package dns

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	defaultPollInterval = time.Second * 5
	defaultPropagationLimit = time.Minute * 2
)

func (f *fixture) setupNamespace(t *testing.T, name string) (string, func()) {
	if _, err := f.clientset.CoreV1().Namespaces().Create(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}); err != nil {
		t.Fatalf("error creating test namespace %q: %v", name, err)
	}

	for _, s := range f.secretFixtures {
		s = s.DeepCopy()
		s.Namespace = name
		if _, err := f.clientset.CoreV1().Secrets(name).Create(s); err != nil {
			t.Fatalf("error creating test secret fixture %q: %v", name, err)
		}
	}

	time.Sleep(time.Second * 1)

	return name, func() {
		f.clientset.CoreV1().Namespaces().Delete(name, nil)
	}
}

func (f *fixture) buildChallengeRequest(t *testing.T, ns string) *cmapi.ChallengeRequest {
	return &cmapi.ChallengeRequest{
		ResourceNamespace: ns,
		ResolvedFQDN: f.resolvedFQDN,
		ResolvedZone: f.resolvedZone,
		AllowAmbientCredentials: f.allowAmbientCredentials,
		Config: f.jsonConfig,
		Challenge: cmapi.Challenge{
			Spec: cmapi.ChallengeSpec{
				Key: "testingkey123",
			},
		},
	}
}

func allConditions(c ...wait.ConditionFunc) wait.ConditionFunc {
	return func() (bool, error) {
		for _, fn := range c {
			ok, err := fn()
			if err != nil || !ok {
				return ok, err
			}
		}
		return true, nil
	}
}

func closingStopCh(t time.Duration) <-chan struct{} {
	stopCh := make(chan struct{})
	go func() {
		defer close(stopCh)
		<-time.After(t)
	}()
	return stopCh
}

func (f *fixture) recordHasPropagatedCheck(fqdn, value string) func() (bool, error) {
	return func() (bool, error) {
		return util.PreCheckDNS(fqdn, value, []string{f.testDNSServer}, true)
	}
}

func (f *fixture) recordHasBeenDeletedCheck(fqdn, value string) func() (bool, error) {
	return func() (bool, error) {
		msg, err := util.DNSQuery(fqdn, dns.TypeTXT, []string{f.testDNSServer}, true)
		if err != nil {
			return false, err
		}
		if msg.Rcode == dns.RcodeNameError {
			return true, nil
		}
		if msg.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("unexpected error from DNS server: %v", dns.RcodeToString[msg.Rcode])
		}
		for _, rr := range msg.Answer {
			txt, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}
			for _, k := range txt.Txt {
				if k == value {
					return false, nil
				}
			}
		}
		return true, nil
	}
}
