package manifests

import (
	"context"
	"fmt"

	"github.com/google/go-github/github"
	flag "github.com/spf13/pflag"
	"golang.org/x/oauth2"
)

type gitHub struct {
	// GitHub token
	token string
}

func (g *gitHub) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&g.token, "github.token", "", "github token used to communicate with GitHub")
}

func (g *gitHub) ValidatePublish() []error {
	var errs []error

	if g.token == "" {
		errs = append(errs, fmt.Errorf("github.token must be set"))
	}

	return errs
}

func (g *gitHub) Validate() []error {
	var errs []error

	return errs
}

func (g *gitHub) Complete() error {
	return nil
}

func (g *gitHub) Client() *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: g.token},
	)
	tc := oauth2.NewClient(context.Background(), ts)

	return github.NewClient(tc)
}
