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

package execute

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

type DNSProvider struct {
	pluginPath       string
	config           []byte
	dns01Nameservers []string
}

func NewDNSProviderCredentials(pluginName string, pluginDirectory string, configJson []byte, nameservers []string) (*DNSProvider, error) {
	if pluginName == "" {
		return nil, fmt.Errorf("execute plugin name missing")
	} else if pluginDirectory == "" {
		return nil, fmt.Errorf("execute plugin directory name missing")
	}

	return &DNSProvider{
		pluginPath:       path.Join(pluginDirectory, pluginName),
		config:           configJson,
		dns01Nameservers: nameservers,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	envs := map[string]string{"EXECUTE_PLUGIN_ACTION": "present",
		"EXECUTE_PLUGIN_DOMAIN": util.UnFqdn(fqdn),
		"EXECUTE_PLUGIN_VALUE":  value,
		"EXECUTE_PLUGIN_TTL":    string(ttl)}
	err, _, _ = execute(c.pluginPath, envs, c.config, 0)

	return err
}

func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, keyAuth, c.dns01Nameservers)
	if err != nil {
		return err
	}

	envs := map[string]string{"EXECUTE_PLUGIN_ACTION": "cleanup",
		"EXECUTE_PLUGIN_DOMAIN": util.UnFqdn(fqdn),
		"EXECUTE_PLUGIN_VALUE":  value,
		"EXECUTE_PLUGIN_TTL":    strconv.Itoa(ttl)}
	err, _, _ = execute(c.pluginPath, envs, c.config, 0)

	return err
}

func execute(binaryPath string, envs map[string]string, config []byte, timeoutSeconds time.Duration) (error, string, string) {
	var timeout time.Duration
	if timeoutSeconds == 0 {
		timeout = 30 * time.Second
	} else {
		timeout = timeoutSeconds * time.Second
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Cmd{
		Path:        binaryPath,
		Env:         envMapToSlice(envs),
		Dir:         os.TempDir(),
		Stdin:       bytes.NewReader(config),
		Stdout:      &stdoutBuf,
		Stderr:      &stderrBuf,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}

	glog.Infof("executing plugin %v with the following arguments: %v", cmd.Path, cmd.Args)

	finished := make(chan bool)
	go func() {
		select {
		case <-finished:
			break
		case <-time.After(timeout):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-finished:
				break
			case <-time.After(5 * time.Second):
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		}
	}()

	status := cmd.Run()
	finished <- true
	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()
	glog.Infof("plugin finished with status: %v, stdout: %v, stderr: %v",
		status, stdout, stderr)

	return status, stdout, stderr
}

func envMapToSlice(envs map[string]string) []string {
	var envSlice []string
	for k, v := range envs {
		envSlice = append(envSlice, strings.TrimSpace(fmt.Sprintf("%s=%s", k, v)))
	}
	return envSlice
}
