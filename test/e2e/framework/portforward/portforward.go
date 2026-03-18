/*
Copyright 2025 The cert-manager Authors.

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

// Package portforward provides a client-go-based port-forward proxy for use
// in e2e tests. It is a shared abstraction used by multiple addons and test
// utilities instead of shelling out to kubectl.
package portforward

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientgoforward "k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// Proxy forwards a single port from a local free port to a target port on a
// specific pod. Call Start to begin forwarding and Stop to tear it down.
type Proxy struct {
	clientset    kubernetes.Interface
	kubeConfig   *rest.Config
	localPort    int
	targetPort   int
	podNamespace string
	podName      string

	stopCh chan struct{}
	mu     sync.Mutex
	doneCh chan error
}

// New allocates a free local port and returns a Proxy ready to forward
// localPort -> targetPort on the given pod. Call Start to begin forwarding.
func New(ctx context.Context, clientset kubernetes.Interface, kubeConfig *rest.Config, podNamespace, podName string, targetPort int) (*Proxy, error) {
	lp, err := freePort(ctx)
	if err != nil {
		return nil, fmt.Errorf("finding free local port: %w", err)
	}
	return &Proxy{
		clientset:    clientset,
		kubeConfig:   kubeConfig,
		localPort:    lp,
		targetPort:   targetPort,
		podNamespace: podNamespace,
		podName:      podName,
		stopCh:       make(chan struct{}),
	}, nil
}

// LocalPort returns the local port that traffic should be sent to.
func (p *Proxy) LocalPort() int { return p.localPort }

// Start begins port-forwarding in the background. It reconnects automatically
// if the connection is dropped (e.g. pod restart) until Stop is called.
func (p *Proxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	select {
	case <-p.stopCh:
		return nil
	default:
	}

	stopCh := p.stopCh
	doneCh := make(chan error, 1)
	p.doneCh = doneCh

	reqURL := p.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(p.podNamespace).
		Name(p.podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(p.kubeConfig)
	if err != nil {
		return err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, reqURL)

	runForwarder := func() error {
		fw, err := clientgoforward.New(dialer, []string{fmt.Sprintf("%d:%d", p.localPort, p.targetPort)}, stopCh, make(chan struct{}), io.Discard, io.Discard)
		if err != nil {
			return fmt.Errorf("creating port-forwarder: %w", err)
		}
		if err := fw.ForwardPorts(); err != nil {
			return fmt.Errorf("forwarding ports: %w", err)
		}
		return nil
	}

	go func() {
		defer close(doneCh)
		for {
			err := runForwarder()
			select {
			case <-stopCh:
				doneCh <- err
				return
			default:
				fmt.Fprintf(ginkgo.GinkgoWriter, "port-forward %s/%s %d->%d: %v\n", p.podNamespace, p.podName, p.localPort, p.targetPort, err)
			}
		}
	}()

	return nil
}

// Stop shuts down the port-forward and waits for the background goroutine to exit.
func (p *Proxy) Stop(ctx context.Context) error {
	close(p.stopCh)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.doneCh == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-p.doneCh:
		if err != nil {
			return fmt.Errorf("port-forward exited with error: %w", err)
		}
	}

	return nil
}

// freePort binds to localhost:0 to let the OS pick a free port, then returns
// it.
func freePort(ctx context.Context) (int, error) {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "localhost:0")
	if err != nil {
		return -1, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
