/*
Copyright 2025 The cert-manager Authors.

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

package collectors

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/labels"

	acmemeta "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
)

var (
	challengeValidStatuses  = [...]acmemeta.State{acmemeta.Ready, acmemeta.Valid, acmemeta.Errored, acmemeta.Expired, acmemeta.Invalid, acmemeta.Processing, acmemeta.Unknown, acmemeta.Pending}
	certChallengeMetricDesc = prometheus.NewDesc("certmanager_certificate_challenge_status", "The status of certificate challenges", []string{"status", "domain", "reason", "processing", "name", "namespace", "type"}, nil)
)

// maxChallengeReasonLabelLen caps the "reason" label: ACME status text can embed HTML
// responses and unbounded detail, which breaks Prometheus scraping and explodes series size.
const maxChallengeReasonLabelLen = 256

// normalizeChallengeReason converts arbitrary challenge reason text into a
// bounded, printable string suitable for use as a Prometheus label value.
func normalizeChallengeReason(reason string) string {
	var b strings.Builder
	if reasonLen := len(reason); reasonLen > maxChallengeReasonLabelLen {
		b.Grow(maxChallengeReasonLabelLen)
	} else {
		b.Grow(reasonLen)
	}

	for _, r := range reason {
		if unicode.IsControl(r) {
			r = ' '
		}
		runeLen := utf8.RuneLen(r)
		if b.Len()+runeLen > maxChallengeReasonLabelLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

type ACMECollector struct {
	challengesLister                 cmacmelisters.ChallengeLister
	certificateChallengeStatusMetric *prometheus.Desc
}

func NewACMECollector(acmeInformers cmacmelisters.ChallengeLister) prometheus.Collector {
	return &ACMECollector{
		challengesLister:                 acmeInformers,
		certificateChallengeStatusMetric: certChallengeMetricDesc,
	}
}

func (ac *ACMECollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ac.certificateChallengeStatusMetric
}

func (ac *ACMECollector) Collect(ch chan<- prometheus.Metric) {
	challengesList, err := ac.challengesLister.List(labels.Everything())
	if err != nil {
		return
	}

	for _, challenge := range challengesList {
		for _, status := range challengeValidStatuses {
			value := 0.0
			if string(challenge.Status.State) == string(status) {
				value = 1.0
			}

			metric := prometheus.MustNewConstMetric(
				ac.certificateChallengeStatusMetric, prometheus.GaugeValue,
				value,
				string(status),
				challenge.Spec.DNSName,
				normalizeChallengeReason(challenge.Status.Reason),
				fmt.Sprint(challenge.Status.Processing),
				challenge.Name,
				challenge.Namespace,
				string(challenge.Spec.Type),
			)

			ch <- metric
		}
	}
}
