/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package fake

import (
	"time"

	"github.com/Venafi/vcert/pkg/endpoint"
)

type Venafi struct {
	PingFn                  func() error
	SignFn                  func([]byte, time.Duration) ([]byte, error)
	ReadZoneConfigurationFn func() (*endpoint.ZoneConfiguration, error)
}

func (v *Venafi) Ping() error {
	return v.PingFn()
}

func (v *Venafi) Sign(b []byte, t time.Duration) ([]byte, error) {
	return v.SignFn(b, t)
}

func (v *Venafi) ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error) {
	return v.ReadZoneConfigurationFn()
}

func (v *Venafi) SetClient(endpoint.Connector) {}
