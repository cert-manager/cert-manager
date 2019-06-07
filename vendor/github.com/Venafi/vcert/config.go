/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vcert

import (
	"fmt"
	"github.com/Venafi/vcert/pkg/endpoint"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"log"
	"os/user"
	"path/filepath"
)

// Config is a basic structure for high level initiating connector to Trust Platform (TPP)/Venafi Cloud
type Config struct {
	// ConnectorType specify what do you want to use. May be "Cloud", "TPP" or "Fake" for development.
	ConnectorType endpoint.ConnectorType
	// BaseUrl should be specified for Venafi Platform. Optional for Cloud implementations that do not use https://venafi.cloud/.
	BaseUrl string
	// Zone is name of a policy zone in Venafi Platform or Cloud. For TPP, if necessary, escape backslash symbols.   For example,  "test\\zone" or `test\zone`.
	Zone string
	// Credentials should contain either User and Password for TPP connections or an APIKey for Cloud.
	Credentials *endpoint.Authentication
	// ConnectionTrust  may contain a trusted CA or certificate of server if you use self-signed certificate.
	ConnectionTrust string // *x509.CertPool
	LogVerbose      bool
}

// LoadFromFile is deprecated. In the future will be rewrited.
func LoadConfigFromFile(path, section string) (cfg Config, err error) {

	if section == "" {
		section = ini.DEFAULT_SECTION
	}
	log.Printf("Loading configuration from %s section %s", path, section)

	fname, err := expand(path)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	iniFile, err := ini.Load(fname)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	err = validateFile(iniFile)
	if err != nil {
		return cfg, fmt.Errorf("failed to load config: %s", err)
	}

	ok := func() bool {
		for _, s := range iniFile.Sections() {
			if s.Name() == section {
				return true
			}
		}
		return false
	}()
	if !ok {
		return cfg, fmt.Errorf("section %s has not been found in %s", section, path)
	}

	var m dict = iniFile.Section(section).KeysHash()

	var connectorType endpoint.ConnectorType
	var baseUrl string
	var auth = &endpoint.Authentication{}
	if m.has("tpp_url") {
		connectorType = endpoint.ConnectorTypeTPP
		baseUrl = m["tpp_url"]
		auth.User = m["tpp_user"]
		auth.Password = m["tpp_password"]
		if m.has("tpp_zone") {
			cfg.Zone = m["tpp_zone"]
		}
		if m.has("cloud_zone") {
			cfg.Zone = m["cloud_zone"]
		}
	} else if m.has("cloud_apikey") {
		connectorType = endpoint.ConnectorTypeCloud
		if m.has("cloud_url") {
			baseUrl = m["cloud_url"]
		}
		auth.APIKey = m["cloud_apikey"]
		if m.has("cloud_zone") {
			cfg.Zone = m["cloud_zone"]
		}
	} else if m.has("test_mode") && m["test_mode"] == "true" {
		connectorType = endpoint.ConnectorTypeFake
	} else {
		return cfg, fmt.Errorf("failed to load config: connector type cannot be defined")
	}

	if m.has("trust_bundle") {
		fname, err := expand(m["trust_bundle"])
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		data, err := ioutil.ReadFile(fname)
		if err != nil {
			return cfg, fmt.Errorf("failed to load trust-bundle: %s", err)
		}
		cfg.ConnectionTrust = string(data)
	}

	cfg.ConnectorType = connectorType
	cfg.Credentials = auth
	cfg.BaseUrl = baseUrl

	return
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

type dict map[string]string

func (d dict) has(key string) bool {
	if _, ok := d[key]; ok {
		return true
	}
	return false
}

type set map[string]bool

func (d set) has(key string) bool {
	if _, ok := d[key]; ok {
		return true
	}
	return false
}

func validateSection(s *ini.Section) error {
	var TPPValidKeys set = map[string]bool{
		"tpp_url":      true,
		"tpp_user":     true,
		"tpp_password": true,
		"tpp_zone":     true,
		"trust_bundle": true,
	}
	var CloudValidKeys set = map[string]bool{
		"trust_bundle": true,
		"cloud_url":    true,
		"cloud_apikey": true,
		"cloud_zone":   true,
	}

	log.Printf("Validating configuration section %s", s.Name())
	var m dict = s.KeysHash()

	if m.has("tpp_url") {
		// looks like TPP config section
		for k := range m {
			if !TPPValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in TPP section %s", k, s.Name())
			}
		}
		if !m.has("tpp_user") {
			return fmt.Errorf("configuration issue in section %s: missing TPP user", s.Name())
		}
		if !m.has("tpp_password") {
			return fmt.Errorf("configuration issue in section %s: missing TPP password", s.Name())
		}
	} else if m.has("cloud_apikey") {
		// looks like Cloud config section
		for k := range m {
			if !CloudValidKeys.has(k) {
				return fmt.Errorf("illegal key '%s' in Cloud section %s", k, s.Name())
			}
		}
	} else if m.has("test_mode") {
		// it's ok
	} else {
		return fmt.Errorf("section %s looks empty", s.Name())
	}
	return nil
}

func validateFile(f *ini.File) error {

	for _, section := range f.Sections() {
		if len(section.Keys()) == 0 {
			if len(f.Sections()) > 1 {
				// empty section is not valid. skipping it if there are more sections in the file
				log.Printf("Warning: empty section %s", section.Name())
				continue
			}
		}
		err := validateSection(section)
		if err != nil {
			return err
		}
	}
	return nil
}
