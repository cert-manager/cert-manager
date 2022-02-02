/*
Copyright 2020 The cert-manager Authors.

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

package vault

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/test/e2e/framework/log"
)

type proxy struct {
	client *vault.Client
	cmd    *exec.Cmd

	ns, podName string
	kubectl     string
	vaultCA     []byte

	listenPort int
	mu         sync.Mutex
	closeCh    chan struct{}
}

func newProxy(ns, podName, kubectl string, vaultCA []byte) *proxy {
	return &proxy{
		ns:      ns,
		podName: podName,
		kubectl: kubectl,
		vaultCA: vaultCA,
		closeCh: make(chan struct{}),
	}
}

func (p *proxy) init() (*vault.Client, error) {
	listenPort, err := freePort()
	if err != nil {
		return nil, err
	}
	p.listenPort = listenPort

	cfg := vault.DefaultConfig()
	cfg.Address = fmt.Sprintf("https://127.0.0.1:%d", p.listenPort)

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(p.vaultCA)
	if ok == false {
		return nil, fmt.Errorf("error loading Vault CA bundle: %s", p.vaultCA)
	}

	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize vault client: %s", err)
	}

	client.SetToken(vaultToken)
	p.client = client

	if err := p.runProxy(); err != nil {
		return nil, fmt.Errorf("failed to start vault port forward: %s", err)
	}

	go p.nurseProxy()

	return client, nil
}

func (p *proxy) vaultCmd() *exec.Cmd {
	args := []string{"port-forward", "-n", p.ns, p.podName, fmt.Sprintf("%d:8200", p.listenPort)}
	return exec.Command(p.kubectl, args...)
}

func (p *proxy) nurseProxy() {
	for {
		kCh := make(chan struct{})
		go func() {
			_ = p.cmd.Wait()
			close(kCh)
		}()

		select {
		// if we are stopping the port forward completely then kill the process and exit
		case <-p.closeCh:
			return

			// if the process died, then attempt to recover it
		case <-kCh:
			if err := p.runProxy(); err != nil {
				log.Logf("failed to recover vault port forward: %s", err)
				return
			}

			// new proxy started, loop again
		}
	}
}

func (p *proxy) callVault(method, url, field string, params map[string]string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	req := p.client.NewRequest(method, url)

	err := req.SetJSONBody(params)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())

	}

	resp, err := p.client.RawRequest(req)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())

	}
	defer resp.Body.Close()

	result := map[string]interface{}{}
	resp.DecodeJSON(&result)

	fieldData := ""
	if field != "" {
		data := result["data"].(map[string]interface{})
		fieldData = data[field].(string)
	}

	return fieldData, err
}

func (p *proxy) clean() {
	close(p.closeCh)

	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Process.Wait()
	}
}

func (p *proxy) runProxy() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := wait.PollImmediate(time.Second, time.Second*10, func() (bool, error) {
		p.cmd = p.vaultCmd()

		err := p.cmd.Start()
		if err != nil {
			log.Logf("failed to start port-forward: %s", err)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return err
	}

	err = wait.PollImmediate(time.Second, time.Second*30, func() (bool, error) {
		// If the response is 400 or higher or can't connect then we get an error.
		// Anything else is considered ready for serving.
		_, err := p.client.Sys().Health()
		if err != nil {
			log.Logf("vault health failed: %s", err)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return err
	}

	return nil
}

func freePort() (int, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		return -1, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}
