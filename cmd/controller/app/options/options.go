package options

import (
	"fmt"
	"time"

	"github.com/spf13/pflag"

	"github.com/jetstack/cert-manager/pkg/util"
)

type ControllerOptions struct {
	APIServerHost            string
	ClusterResourceNamespace string

	LeaderElect                 bool
	LeaderElectionNamespace     string
	LeaderElectionLeaseDuration time.Duration
	LeaderElectionRenewDeadline time.Duration
	LeaderElectionRetryPeriod   time.Duration

	ACMEHTTP01SolverImage string

	ClusterIssuerAmbientCredentials bool
	IssuerAmbientCredentials        bool

	// Default issuer/certificates details consumed by ingress-shim
	DefaultIssuerName                  string
	DefaultIssuerKind                  string
	DefaultACMEIssuerChallengeType     string
	DefaultACMEIssuerDNS01ProviderName string
}

const (
	defaultAPIServerHost            = ""
	defaultClusterResourceNamespace = "kube-system"

	defaultLeaderElect                 = true
	defaultLeaderElectionNamespace     = "kube-system"
	defaultLeaderElectionLeaseDuration = 15 * time.Second
	defaultLeaderElectionRenewDeadline = 10 * time.Second
	defaultLeaderElectionRetryPeriod   = 2 * time.Second

	defaultClusterIssuerAmbientCredentials = true
	defaultIssuerAmbientCredentials        = false

	defaultTLSACMEIssuerName           = ""
	defaultTLSACMEIssuerKind           = "Issuer"
	defaultACMEIssuerChallengeType     = "http01"
	defaultACMEIssuerDNS01ProviderName = ""
)

var (
	defaultACMEHTTP01SolverImage = fmt.Sprintf("quay.io/jetstack/cert-manager-acmesolver:%s", util.AppVersion)
)

func NewControllerOptions() *ControllerOptions {
	return &ControllerOptions{
		APIServerHost:                      defaultAPIServerHost,
		ClusterResourceNamespace:           defaultClusterResourceNamespace,
		LeaderElect:                        defaultLeaderElect,
		LeaderElectionNamespace:            defaultLeaderElectionNamespace,
		LeaderElectionLeaseDuration:        defaultLeaderElectionLeaseDuration,
		LeaderElectionRenewDeadline:        defaultLeaderElectionRenewDeadline,
		LeaderElectionRetryPeriod:          defaultLeaderElectionRetryPeriod,
		ClusterIssuerAmbientCredentials:    defaultClusterIssuerAmbientCredentials,
		IssuerAmbientCredentials:           defaultIssuerAmbientCredentials,
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
	fs.StringVar(&s.ClusterResourceNamespace, "cluster-resource-namespace", defaultClusterResourceNamespace, ""+
		"Namespace to store resources owned by cluster scoped resources such as ClusterIssuer in. "+
		"This must be specified if ClusterIssuers are enabled.")
	fs.BoolVar(&s.LeaderElect, "leader-elect", true, ""+
		"If true, cert-manager will perform leader election between instances to ensure no more "+
		"than one instance of cert-manager operates at a time")
	fs.StringVar(&s.LeaderElectionNamespace, "leader-election-namespace", defaultLeaderElectionNamespace, ""+
		"Namespace used to perform leader election. Only used if leader election is enabled")
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

	fs.StringVar(&s.ACMEHTTP01SolverImage, "acme-http01-solver-image", defaultACMEHTTP01SolverImage, ""+
		"The docker image to use to solve ACME HTTP01 challenges. You most likely will not "+
		"need to change this parameter unless you are testing a new feature or developing cert-manager.")

	fs.BoolVar(&s.ClusterIssuerAmbientCredentials, "cluster-issuer-ambient-credentials", defaultClusterIssuerAmbientCredentials, ""+
		"Whether a cluster-issuer may make use of ambient credentials for issuers. 'Ambient Credentials' are credentials drawn from the environment, metadata services, or local files which are not explicitly configured in the ClusterIssuer API object. "+
		"When this flag is enabled, the following sources for credentials are also used: "+
		"AWS - All sources the Go SDK defaults to, notably including any EC2 IAM roles available via instance metadata.")
	fs.BoolVar(&s.IssuerAmbientCredentials, "issuer-ambient-credentials", defaultIssuerAmbientCredentials, ""+
		"Whether an issuer may make use of ambient credentials. 'Ambient Credentials' are credentials drawn from the environment, metadata services, or local files which are not explicitly configured in the Issuer API object. "+
		"When this flag is enabled, the following sources for credentials are also used: "+
		"AWS - All sources the Go SDK defaults to, notably including any EC2 IAM roles available via instance metadata.")

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
	switch o.DefaultIssuerKind {
	case "Issuer":
	case "ClusterIssuer":
	default:
		return fmt.Errorf("invalid default issuer kind: %v", o.DefaultIssuerKind)
	}
	return nil
}
