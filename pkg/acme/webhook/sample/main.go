package main

import (
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/sample/cloudflare"
)

const GroupName = "solvers.acme.cert-manager.io"

func main() {
	cmd.RunWebhookServer(GroupName,
		&cloudflare.Solver{},
	)
}
