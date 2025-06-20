package collectors

import (
	"fmt"
	"log"

	"k8s.io/apimachinery/pkg/labels"

	acmemeta "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmacmeinformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions/acme/v1"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	challengeValidStatuses  = [...]acmemeta.State{acmemeta.Ready, acmemeta.Valid, acmemeta.Errored, acmemeta.Expired, acmemeta.Invalid, acmemeta.Processing, acmemeta.Unknown, acmemeta.Pending}
	certChallengeMetricDesc = prometheus.NewDesc("certmanager_certificate_challenge_status", "The status of certificate challenges", []string{"status", "domain", "reason", "processing", "name", "namespace", "type"}, nil)
)

type AcmeCollector struct {
	challengesInformer               cmacmeinformers.ChallengeInformer
	certificateChallengeStatusMetric *prometheus.Desc
}

func NewACMECollector(acmeInformers cmacmeinformers.ChallengeInformer) prometheus.Collector {
	return &AcmeCollector{
		challengesInformer:               acmeInformers,
		certificateChallengeStatusMetric: *&certChallengeMetricDesc,
	}
}

func (ac *AcmeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ac.certificateChallengeStatusMetric
}

func (ac *AcmeCollector) Collect(ch chan<- prometheus.Metric) {
	// if !ac.challengesInformer.Informer().HasSynced() {
	// 	return
	// }
	//
	log.Println("Entering here")

	challengesList, err := ac.challengesInformer.Lister().List(labels.Everything())
	if err != nil {
		log.Printf("%v\n", err)
		fmt.Println(err)
		return
	}

	log.Printf("Listing challenges %v", challengesList)

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
				challenge.Status.Reason,
				fmt.Sprint(challenge.Status.Processing),
				challenge.Name,
				challenge.Namespace,
				string(challenge.Spec.Type),
			)

			log.Printf("Adding metric: %v\n", metric)

			ch <- metric
		}
	}
}
