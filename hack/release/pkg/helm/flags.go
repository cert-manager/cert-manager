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

package helm

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/jetstack/cert-manager/hack/release/pkg/bazel"
	logf "github.com/jetstack/cert-manager/hack/release/pkg/log"
)

var (
	Default = &Helm{}
	log     = logf.Log.WithName("helm")
)

type Helm struct {
}

func (g *Helm) AddFlags(fs *flag.FlagSet) {
}

func (g *Helm) Validate() []error {
	var errs []error

	return errs
}

func (g *Helm) Complete() error {
	return nil
}

func (g *Helm) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	if ctx == nil {
		ctx = context.Background()
	}
	return bazel.Default.Run(ctx, "//hack/bin:helm", append([]string{"--"}, args...)...)
}

func (g *Helm) Init(ctx context.Context, clientOnly bool, args ...string) *exec.Cmd {
	tmpl := []string{"init"}
	if clientOnly {
		tmpl = append(tmpl, "--client-only")
	}
	return g.Cmd(ctx, append(tmpl, args...)...)
}

func (g *Helm) Template(ctx context.Context, output io.Writer, target string, args ...string) *exec.Cmd {
	cmd := g.Cmd(ctx, append([]string{"template", target}, args...)...)
	cmd.Stdout = output
	return cmd
}

func (g *Helm) TemplateE(ctx context.Context, target string, args ...string) (string, error) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := g.Template(ctx, f, target, args...).Run(); err != nil {
		return "", err
	}

	return filepath.Abs(f.Name())
}

// Package will construct a new exec.Cmd that will run "helm package"
func (g *Helm) Package(ctx context.Context, target, outputDir string, args ...string) *exec.Cmd {
	return g.Cmd(ctx, append([]string{"package", target, "--destination", outputDir}, args...)...)
}

func (g *Helm) InitE(ctx context.Context, clientOnly bool, args ...string) error {
	return g.Init(ctx, clientOnly, args...).Run()
}

func (g *Helm) PackageE(ctx context.Context, target string, outputDir string, args ...string) (string, error) {
	if outputDir == "" {
		var err error
		outputDir, err = ioutil.TempDir("", "cert-manager-release-")
		if err != nil {
			return "", err
		}
	}

	// This logic has to be horribly complicated as Helm does not automatically
	// honour the `--version` field for *subcharts* named with file://.
	// To work around this, we find all subcharts and run `helm package` on
	// each one, setting the `--version` flag.
	// We then collate all these packaged charts into the 'charts/' directory
	// before packaging the actual chart.

	var childPackagePaths []string
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if filepath.Base(path) == "Chart.yaml" && filepath.Clean(target) != filepath.Dir(path) {
			log.Info("processing child chart", "path", path)

			dir, err := ioutil.TempDir("", "")
			if err != nil {
				return err
			}
			packagePath, err := g.packageChart(ctx, filepath.Dir(path), dir, args...)
			if err != nil {
				return err
			}

			childPackagePaths = append(childPackagePaths, packagePath)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	log.Info("built child packages", "packages", childPackagePaths)
	subchartDir := filepath.Join(target, "charts")
	log.Info("cleaning subcharts directory", "path", subchartDir)
	if err := os.RemoveAll(subchartDir); err != nil {
		return "", fmt.Errorf("failed to clean up existing subchart dir: %v", err)
	}
	if err := os.MkdirAll(subchartDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create new subchart dir: %v", err)
	}

	for _, path := range childPackagePaths {
		log.Info("copying file", "input", path)
		input, err := ioutil.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("error reading file: %v", err)
		}

		outFile := filepath.Join(subchartDir, filepath.Base(path))
		if err := ioutil.WriteFile(outFile, input, 0644); err != nil {
			return "", fmt.Errorf("error writing new file: %v", err)
		}
		if err := os.RemoveAll(path); err != nil {
			return "", fmt.Errorf("error removing old file: %v", err)
		}
		log.Info("copied file", "file", outFile)
	}

	return g.packageChart(ctx, target, outputDir, args...)
}

func (g *Helm) packageChart(ctx context.Context, target, outputDir string, args ...string) (string, error) {
	if err := g.Package(ctx, target, outputDir, args...).Run(); err != nil {
		return "", err
	}

	files, err := ioutil.ReadDir(outputDir)
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if strings.HasSuffix(f.Name(), ".tgz") {
			return path.Join(outputDir, f.Name()), nil
		}
	}

	return "", fmt.Errorf("cannot find chart package output file in directory %q", outputDir)
}
