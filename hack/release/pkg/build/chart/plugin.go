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

package chart

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cloud.google.com/go/storage"
	flag "github.com/spf13/pflag"

	"github.com/jetstack/cert-manager/hack/release/pkg/flags"
	"github.com/jetstack/cert-manager/hack/release/pkg/helm"
	logf "github.com/jetstack/cert-manager/hack/release/pkg/log"
)

var (
	Default = &Plugin{}

	log = logf.Log.WithName("chart")
)

type Plugin struct {
	// chart.output-dir
	OutputDir string

	// Name of the GCS bucket to upload charts to
	Bucket string

	gcsClient  *storage.Client
	outputFile string
}

func (g *Plugin) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&g.OutputDir, "chart.output-dir", "", "optional output directory to specify where to build the helm chart gz file")
	fs.StringVar(&g.Bucket, "chart.bucket", "jetstack-chart-museum", "google cloud storage bucket to publish helm charts to")
}

func (g *Plugin) Validate() []error {
	var errs []error

	return errs
}

func (g *Plugin) InitPublish() []error {
	if g.Bucket == "" {
		return []error{fmt.Errorf("chart.bucket must be specified")}
	}

	ctx := context.Background()
	// Creates a client.
	client, err := storage.NewClient(ctx)
	if err != nil {
		return []error{fmt.Errorf("failed to create client: %v", err)}
	}

	g.gcsClient = client

	return nil
}

func (g *Plugin) Build(ctx context.Context) error {
	if err := helm.Default.InitE(ctx, true); err != nil {
		return err
	}

	// TODO: the AppVersion *must* be semver compatible else this call will fail.
	outputFile, err := helm.Default.PackageE(ctx, flags.Default.ChartPath, g.OutputDir,
		"--version="+flags.Default.AppVersion,
		"--app-version="+flags.Default.AppVersion,
	)
	if err != nil {
		return err
	}

	log.Info("wrote output package", "filename", outputFile)
	g.outputFile = outputFile

	return nil
}

func (g *Plugin) Publish(ctx context.Context) error {
	log.Info("running publish for chart plugin")
	// Creates a Bucket instance.
	bucket := g.gcsClient.Bucket(g.Bucket)
	log.Info("publishing to bucket", "bucket", g.Bucket)

	filename := filepath.Base(g.outputFile)
	w := bucket.Object(filename).NewWriter(ctx)
	log.Info("writing output file to GCS", "name", filename)
	defer w.Close()
	in, err := os.Open(g.outputFile)
	if err != nil {
		return fmt.Errorf("error opening output file: %v", err)
	}
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("error closing file: %v", err)
	}

	log.Info("published chart to bucket", "bucket", g.Bucket, "path", bucket.Object(filename).ObjectName())

	return nil
}

func (g *Plugin) Complete() error {
	return nil
}
