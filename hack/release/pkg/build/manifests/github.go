/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package manifests

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/go-github/github"
	flag "github.com/spf13/pflag"
	"golang.org/x/oauth2"
)

type gitHub struct {
	tokenFile string

	// GitHub token
	token string
}

func (g *gitHub) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&g.tokenFile, "github.token-file", "/etc/github/token", "path to a file containing the github token used to communicate with GitHub")
}

func (g *gitHub) ValidatePublish() []error {
	var errs []error

	if g.tokenFile == "" {
		errs = append(errs, fmt.Errorf("github.token-file must be set"))
		return errs
	}

	b, err := ioutil.ReadFile(g.tokenFile)
	if err != nil {
		errs = append(errs, fmt.Errorf("error reading github token from file: %v", err))
	}

	g.token = strings.TrimSpace(string(b))

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
