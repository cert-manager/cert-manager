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
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-github/github"
	flag "github.com/spf13/pflag"

	"github.com/jetstack/cert-manager/hack/release/pkg/flags"
	"github.com/jetstack/cert-manager/hack/release/pkg/helm"
	logf "github.com/jetstack/cert-manager/hack/release/pkg/log"
)

var (
	Default  = &Plugin{}
	variants = map[string][]string{
		"cert-manager.yaml":            {},
		"cert-manager-no-webhook.yaml": {"--set=webhook.enabled=false"},
		"cert-manager-openshift.yaml":  {"--set=global.isOpenshift=true"},
	}

	log = logf.Log.WithName("manifests")
)

type Plugin struct {
	// helm.path
	HelmPath string

	// chart.path
	ChartPath string

	// Organisation to publish to
	Org string

	// Repository to publish to
	Repo string

	github    *gitHub
	releaseID int64
	// variants is a map of variant name to a path containing the generated
	// manifest data
	variants map[string]string
}

func (p *Plugin) AddFlags(fs *flag.FlagSet) {
	p.github = &gitHub{}
	p.variants = make(map[string]string)
	p.github.AddFlags(fs)

	fs.StringVar(&p.Org, "manifests.org", "jetstack", "GitHub organisation name to publish manifests release to")
	fs.StringVar(&p.Repo, "manifests.repo", "cert-manager", "GitHub repository name to publish manifests release to")
}

func (p *Plugin) Validate() []error {
	var errs []error
	errs = append(errs, p.github.Validate()...)
	return errs
}

func (p *Plugin) InitPublish() []error {
	var errs []error

	errs = append(errs, p.github.ValidatePublish()...)
	if p.Org == "" {
		errs = append(errs, fmt.Errorf("manifests.org must be set"))
	}
	if p.Repo == "" {
		errs = append(errs, fmt.Errorf("manifests.repo must be set"))
	}
	if len(errs) > 0 {
		return errs
	}

	release, resp, err := p.github.Client().Repositories.GetReleaseByTag(context.Background(), p.Org, p.Repo, flags.Default.AppVersion)
	if err != nil {
		return []error{err}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return []error{fmt.Errorf("unexpected response code %d", resp.StatusCode)}
	}
	p.releaseID = *release.ID

	return errs
}

func (p *Plugin) Build(ctx context.Context) error {
	if err := helm.Default.InitE(ctx, true); err != nil {
		return err
	}

	// TODO: the AppVersion *must* be semver compatible else this call will fail.
	packagedChart, err := helm.Default.PackageE(ctx, flags.Default.ChartPath, "",
		"--version="+flags.Default.AppVersion,
		"--app-version="+flags.Default.AppVersion,
	)
	if err != nil {
		return err
	}

	for n, args := range variants {
		outFile, err := helm.Default.TemplateE(ctx, packagedChart, append([]string{
			"--kube-version=1.9",
			"--namespace=cert-manager",
			"--name=cert-manager",
			fmt.Sprintf("--values=%s", filepath.Join(flags.Default.RepoRoot, "deploy", "manifests", "helm-values.yaml")),
		}, args...)...)
		if err != nil {
			return fmt.Errorf("error building manifest variant %q: %v", n, err)
		}

		b, err := concatFiles(
			path.Join(flags.Default.RepoRoot, "deploy", "manifests", "00-crds.yaml"),
			path.Join(flags.Default.RepoRoot, "deploy", "manifests", "01-namespace.yaml"),
			outFile,
		)
		if err != nil {
			return err
		}

		if err := ioutil.WriteFile(outFile, []byte(b.String()), 0644); err != nil {
			return fmt.Errorf("error writing concatenated file: %v", err)
		}

		p.variants[n] = outFile
		log.Info("generated manifest for variant", "variant", n, "path", outFile)
	}

	return nil
}

func (p *Plugin) Publish(ctx context.Context) error {
	for n, filepath := range p.variants {
		f, err := os.Open(filepath)
		if err != nil {
			return err
		}
		asset, resp, err := p.github.Client().Repositories.UploadReleaseAsset(
			context.Background(),
			p.Org,
			p.Repo,
			p.releaseID,
			&github.UploadOptions{
				Name: n,
			},
			f)
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("unexpected response code %d", resp.StatusCode)
		}
		log.Info("uploaded asset to github", "name", asset.Name, "url", asset.BrowserDownloadURL)
	}
	return nil
}

func (p *Plugin) Complete() error {
	return p.github.Complete()
}

func concatFiles(files ...string) (*strings.Builder, error) {
	builder := &strings.Builder{}
	for _, f := range files {
		d, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, err
		}

		if _, err := builder.Write(d); err != nil {
			return nil, err
		}
	}
	return builder, nil
}
