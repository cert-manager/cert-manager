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

	"k8s.io/apimachinery/pkg/runtime/serializer"

	config "github.com/cert-manager/cert-manager/internal/apis/config/cainjector"
	"github.com/cert-manager/cert-manager/internal/apis/config/cainjector/scheme"
)

type CAInjectorConfigFile struct {
	Config *config.CAInjectorConfiguration
}

func New() *CAInjectorConfigFile {
	return &CAInjectorConfigFile{
		Config: &config.CAInjectorConfiguration{},
	}
}

func decodeConfiguration(data []byte) (*config.CAInjectorConfiguration, error) {
	_, codec, err := scheme.NewSchemeAndCodecs(serializer.EnableStrict)
	if err != nil {
		return nil, err
	}

	obj, _, err := codec.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	c, ok := obj.(*config.CAInjectorConfiguration)
	if !ok {
		return nil, fmt.Errorf("failed to cast object to ControllerConfiguration, unexpected type")
	}

	return c, nil

}

func (cfg *CAInjectorConfigFile) DecodeAndConfigure(data []byte) error {
	config, err := decodeConfiguration(data)
	if err != nil {
		return err
	}
	cfg.Config = config

	return nil
}

func (cfg *CAInjectorConfigFile) GetPathRefs() ([]*string, error) {
	paths, err := CAInjectorConfigurationPathRefs(cfg.Config)
	if err != nil {
		return nil, err
	}
	return paths, err

}

// CAInjectorConfigurationPathRefs returns pointers to all the CAInjectorConfiguration fields that contain filepaths.
// You might use this, for example, to resolve all relative paths against some common root before
// passing the configuration to the application. This method must be kept up to date as new fields are added.
func CAInjectorConfigurationPathRefs(cfg *config.CAInjectorConfiguration) ([]*string, error) {
	return []*string{
		&cfg.MetricsTLSConfig.Filesystem.KeyFile,
		&cfg.MetricsTLSConfig.Filesystem.CertFile,
		&cfg.KubeConfig,
	}, nil
}
