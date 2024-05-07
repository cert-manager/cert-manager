/*
Copyright 2020 The cert-manager Authors.

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

// package dns contains a framework for testing ACME DNS solver implementations.
// Used by both internal and external solvers.
package dns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	defaultPollInterval     = time.Second * 3
	defaultPropagationLimit = time.Minute * 2
)

func (f *fixture) setupNamespace(t *testing.T, name string) (string, func()) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if _, err := f.clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{}); err != nil {
		t.Fatalf("error creating test namespace %q: %v", name, err)
	}

	kubectl, err := f.adminUser.Kubectl()
	if err != nil {
		t.Fatalf("enable to create kubectl instance: %s", err)
	}

	if f.kubectlManifestsPath != "" {
		if err := filepath.Walk(f.kubectlManifestsPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || filepath.Base(path) == "config.json" {
				return nil
			}

			switch filepath.Ext(path) {
			case ".json", ".yaml", ".yml":
			default:
				t.Logf("skipping file %q with unrecognised extension", path)
				return nil
			}
			_, _, err = kubectl.Run("apply", "--namespace", name, "-f", path)
			if err != nil {
				return err
			}

			t.Logf("created fixture %q", name)
			return nil
		}); err != nil {
			t.Fatalf("error creating test fixtures: %v", err)
		}

		// wait for the test suite informers to relist
		time.Sleep(time.Second * 1)
	}

	return name, func() {
		f.clientset.CoreV1().Namespaces().Delete(context.TODO(), name, metav1.DeleteOptions{})
	}
}

func (f *fixture) buildChallengeRequest(t *testing.T, ns string) *whapi.ChallengeRequest {
	return &whapi.ChallengeRequest{
		ResourceNamespace:       ns,
		ResolvedFQDN:            f.resolvedFQDN,
		ResolvedZone:            f.resolvedZone,
		AllowAmbientCredentials: f.allowAmbientCredentials,
		Config:                  f.jsonConfig,
		DNSName:                 f.dnsName,
		Key:                     f.dnsChallengeKey,
	}
}

func allConditions(c ...wait.ConditionWithContextFunc) wait.ConditionWithContextFunc {
	return func(ctx context.Context) (bool, error) {
		for _, fn := range c {
			ok, err := fn(ctx)
			if err != nil || !ok {
				return ok, err
			}
		}
		return true, nil
	}
}

func (f *fixture) recordHasPropagatedCheck(fqdn, value string) func(ctx context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		return util.PreCheckDNS(ctx, fqdn, value, []string{f.testDNSServer}, *f.useAuthoritative)
	}
}

func (f *fixture) recordHasBeenDeletedCheck(fqdn, value string) func(ctx context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		msg, err := util.DNSQuery(ctx, fqdn, dns.TypeTXT, []string{f.testDNSServer}, *f.useAuthoritative)
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

func (f *fixture) getPollInterval() time.Duration {
	if f.pollInterval != 0 {
		return f.pollInterval
	} else {
		return defaultPollInterval
	}
}

func (f *fixture) getPropagationLimit() time.Duration {
	if f.propagationLimit != 0 {
		return f.propagationLimit
	} else {
		return defaultPropagationLimit
	}
}
