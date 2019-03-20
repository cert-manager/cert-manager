package main

import (
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/acmedns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/akamai"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/azuredns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/clouddns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/cloudflare"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/digitalocean"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/rfc2136"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/route53"
	webhookslv "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/webhook"
)

const GroupName = "solvers.acme.cert-manager.io"

func main() {
	cmd.RunWebhookServer(GroupName,
		&acmedns.Solver{},
		&akamai.Solver{},
		&azuredns.Solver{},
		&clouddns.Solver{},
		&cloudflare.Solver{},
		&digitalocean.Solver{},
		&rfc2136.Solver{},
		&route53.Solver{},
		&webhookslv.Webhook{},
	)
}
