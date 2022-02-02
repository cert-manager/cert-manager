/*
Copyright 2021 The cert-manager Authors.

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

package configfile

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime/serializer"

	config "github.com/cert-manager/cert-manager/internal/apis/config/webhook"
	"github.com/cert-manager/cert-manager/internal/apis/config/webhook/scheme"
)

// Filesystem is an interface used to mock out calls to ReadFile
type Filesystem interface {
	ReadFile(filename string) ([]byte, error)
}

type realFS struct{}

func (fs realFS) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// NewRealFS builds a Filesystem that wraps around `ioutil.ReadFile`.
func NewRealFS() Filesystem {
	return realFS{}
}

type Loader interface {
	Load() (*config.WebhookConfiguration, error)
}

type fsLoader struct {
	fs       Filesystem
	filename string
	codec    *serializer.CodecFactory
}

var _ Loader = &fsLoader{}

func (f *fsLoader) Load() (*config.WebhookConfiguration, error) {
	data, err := f.fs.ReadFile(f.filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook config file %q, error: %v", f.filename, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("webhook config file %q was empty", f.filename)
	}

	cfg, err := decodeWebhookConfiguration(f.codec, data)
	if err != nil {
		return nil, err
	}

	// make all paths absolute
	resolveRelativePaths(webhookConfigurationPathRefs(cfg), filepath.Dir(f.filename))
	return cfg, nil
}

func NewFSLoader(fs Filesystem, name string) (Loader, error) {
	_, webhookCodec, err := scheme.NewSchemeAndCodecs(serializer.EnableStrict)
	if err != nil {
		return nil, err
	}

	return &fsLoader{
		fs:       fs,
		filename: name,
		codec:    webhookCodec,
	}, nil
}

func resolveRelativePaths(paths []*string, root string) {
	for _, path := range paths {
		// leave empty paths alone, "no path" is a valid input
		// do not attempt to resolve paths that are already absolute
		if len(*path) > 0 && !filepath.IsAbs(*path) {
			*path = filepath.Join(root, *path)
		}
	}
}

func decodeWebhookConfiguration(codec *serializer.CodecFactory, data []byte) (*config.WebhookConfiguration, error) {
	obj, gvk, err := codec.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	internalObj, ok := obj.(*config.WebhookConfiguration)
	if !ok {
		return nil, fmt.Errorf("failed to cast object to WebhookConfiguration, unexpected type: %v", gvk)
	}

	return internalObj, nil
}

// webhookConfigurationPathRefs returns pointers to all the WebhookConfiguration fields that contain filepaths.
// You might use this, for example, to resolve all relative paths against some common root before
// passing the configuration to the application. This method must be kept up to date as new fields are added.
func webhookConfigurationPathRefs(cfg *config.WebhookConfiguration) []*string {
	return []*string{
		&cfg.TLSConfig.Filesystem.KeyFile,
		&cfg.TLSConfig.Filesystem.CertFile,
		&cfg.KubeConfig,
	}
}
