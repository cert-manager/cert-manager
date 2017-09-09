package options

import (
	"time"

	"github.com/spf13/pflag"
)

type ControllerOptions struct {
	APIServerHost string
	Namespace     string

	LeaderElect                 bool
	LeaderElectionNamespace     string
	LeaderElectionLeaseDuration time.Duration
	LeaderElectionRenewDeadline time.Duration
	LeaderElectionRetryPeriod   time.Duration
}

const (
	defaultAPIServerHost = ""
	defaultNamespace     = ""

	defaultLeaderElect                 = true
	defaultLeaderElectionNamespace     = "kube-system"
	defaultLeaderElectionLeaseDuration = 15 * time.Second
	defaultLeaderElectionRenewDeadline = 10 * time.Second
	defaultLeaderElectionRetryPeriod   = 2 * time.Second
)

func NewControllerOptions() *ControllerOptions {
	return &ControllerOptions{
		APIServerHost:               defaultAPIServerHost,
		Namespace:                   defaultNamespace,
		LeaderElect:                 defaultLeaderElect,
		LeaderElectionNamespace:     defaultLeaderElectionNamespace,
		LeaderElectionLeaseDuration: defaultLeaderElectionLeaseDuration,
		LeaderElectionRenewDeadline: defaultLeaderElectionRenewDeadline,
		LeaderElectionRetryPeriod:   defaultLeaderElectionRetryPeriod,
	}
}

func (s *ControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.APIServerHost, "master", defaultAPIServerHost, ""+
		"Optional apiserver host address to connect to. If not specified, autoconfiguration "+
		"will be attempted.")
	fs.StringVar(&s.Namespace, "namespace", "", defaultNamespace+
		"Optional namespace to monitor resources within. This can be used to limit the scope "+
		"of cert-manager to a single namespace. If not specified, all namespaces will be watched")

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
}

func (o *ControllerOptions) Validate() error {
	return nil
}
