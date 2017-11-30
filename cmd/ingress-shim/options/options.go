package options

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

type ControllerOptions struct {
	APIServerHost string
	Namespace     string

	LeaderElect                 bool
	LeaderElectionNamespace     string
	LeaderElectionLeaseDuration time.Duration
	LeaderElectionRenewDeadline time.Duration
	LeaderElectionRetryPeriod   time.Duration

	DefaultIssuerName                  string
	DefaultIssuerKind                  string
	DefaultACMEIssuerChallengeType     string
	DefaultACMEIssuerDNS01ProviderName string
}

const (
	defaultAPIServerHost = ""
	defaultNamespace     = ""

	defaultLeaderElect                 = true
	defaultLeaderElectionNamespace     = "kube-system"
	defaultLeaderElectionLeaseDuration = 15 * time.Second
	defaultLeaderElectionRenewDeadline = 10 * time.Second
	defaultLeaderElectionRetryPeriod   = 2 * time.Second

	defaultTLSACMEIssuerName           = ""
	defaultTLSACMEIssuerKind           = "Issuer"
	defaultACMEIssuerChallengeType     = "http01"
	defaultACMEIssuerDNS01ProviderName = ""
)

func NewControllerOptions() *ControllerOptions {
	return &ControllerOptions{
		APIServerHost:                      defaultAPIServerHost,
		Namespace:                          defaultNamespace,
		LeaderElect:                        defaultLeaderElect,
		LeaderElectionNamespace:            defaultLeaderElectionNamespace,
		LeaderElectionLeaseDuration:        defaultLeaderElectionLeaseDuration,
		LeaderElectionRenewDeadline:        defaultLeaderElectionRenewDeadline,
		LeaderElectionRetryPeriod:          defaultLeaderElectionRetryPeriod,
		DefaultIssuerName:                  defaultTLSACMEIssuerName,
		DefaultIssuerKind:                  defaultTLSACMEIssuerKind,
		DefaultACMEIssuerChallengeType:     defaultACMEIssuerChallengeType,
		DefaultACMEIssuerDNS01ProviderName: defaultACMEIssuerDNS01ProviderName,
	}
}

func (s *ControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.APIServerHost, "master", defaultAPIServerHost, ""+
		"Optional apiserver host address to connect to. If not specified, autoconfiguration "+
		"will be attempted.")
	fs.StringVar(&s.Namespace, "namespace", defaultNamespace, ""+
		"Optional namespace to monitor resources within. This can be used to limit the scope "+
		"of ingress-annotation-controller to a single namespace. If not specified, all namespaces will be watched.")

	fs.BoolVar(&s.LeaderElect, "leader-elect", true, ""+
		"If true, ingress-annotation-controller will perform leader election between instances to ensure no more "+
		"than one instance of cert-manager operates at a time.")
	fs.StringVar(&s.LeaderElectionNamespace, "leader-election-namespace", defaultLeaderElectionNamespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled.")
	fs.DurationVar(&s.LeaderElectionLeaseDuration, "leader-election-lease-duration", defaultLeaderElectionLeaseDuration, ""+
		"The duration that non-leader candidates will wait after observing a leadership "+
		"renewal until attempting to acquire leadership of a led but unrenewed leader "+
		"slot. This is effectively the maximum duration that a leader can be stopped "+
		"before it is replaced by another candidate. This is only applicable if leader "+
		"election is enabled.")
	fs.DurationVar(&s.LeaderElectionRenewDeadline, "leader-election-renew-deadline", defaultLeaderElectionRenewDeadline, ""+
		"The interval between attempts by the acting master to renew a leadership slot "+
		"before it stops leading. This must be less than or equal to the lease duration. "+
		"This is only applicable if leader election is enabled.")
	fs.DurationVar(&s.LeaderElectionRetryPeriod, "leader-election-retry-period", defaultLeaderElectionRetryPeriod, ""+
		"The duration the clients should wait between attempting acquisition and renewal "+
		"of a leadership. This is only applicable if leader election is enabled.")

	fs.StringVar(&s.DefaultIssuerName, "default-issuer-name", defaultTLSACMEIssuerName, ""+
		"Name of the Issuer to use when the tls is requested but issuer name is not specified on the ingress resource.")
	fs.StringVar(&s.DefaultIssuerKind, "default-issuer-kind", defaultTLSACMEIssuerKind, ""+
		"Kind of the Issuer to use when the tls is requested but issuer kind is not specified on the ingress resource.")
	fs.StringVar(&s.DefaultACMEIssuerChallengeType, "default-acme-issuer-challenge-type", defaultACMEIssuerChallengeType, ""+
		"The ACME challenge type to use when tls is requested for an ACME Issuer but is not specified on the ingress resource.")
	fs.StringVar(&s.DefaultACMEIssuerDNS01ProviderName, "default-acme-issuer-dns01-provider-name", defaultACMEIssuerDNS01ProviderName, ""+
		"Required if --default-acme-issuer-challenge-type is set to dns01. The DNS01 provider to use for ingresses using ACME dns01 "+
		"validation that do not explicitly state a dns provider.")
}

func (o *ControllerOptions) Validate() error {
	var errs []error

	switch o.DefaultACMEIssuerChallengeType {
	case "dns01", "http01", "":
	default:
		errs = append(errs, fmt.Errorf("--default-acme-issuer-challenge-type must be one of 'http01', 'dns01' or not set"))
	}

	if o.DefaultACMEIssuerChallengeType == "dns01" {
		if o.DefaultACMEIssuerDNS01ProviderName == "" {
			errs = append(errs, fmt.Errorf("--default-acme-issuer-dns01-provider-name must be set when --default-acme-issuer-challenge-type is set to dns01"))
		}
	}

	return utilerrors.NewAggregate(errs)
}
