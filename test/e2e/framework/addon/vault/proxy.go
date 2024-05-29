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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type proxy struct {
	clientset  kubernetes.Interface
	kubeConfig *rest.Config
	listenPort int

	podNamespace, podName string

	stopCh chan struct{}
	mu     sync.Mutex
	doneCh chan error
}

func newProxy(
	clientset kubernetes.Interface,
	kubeConfig *rest.Config,
	podNamespace, podName string,
) *proxy {
	freePort, err := freePort()
	if err != nil {
		panic(err)
	}

	return &proxy{
		clientset:  clientset,
		kubeConfig: kubeConfig,

		podNamespace: podNamespace,
		podName:      podName,
		listenPort:   freePort,

		stopCh: make(chan struct{}),
	}
}

func freePort() (int, error) {
	// Reserve a port for the proxy.
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return -1, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (p *proxy) start() error {
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
		fw, err := portforward.New(dialer, []string{fmt.Sprintf("%d:8200", p.listenPort)}, stopCh, make(chan struct{}), io.Discard, io.Discard)
		if err != nil {
			return fmt.Errorf("port forwarder creation error: %v", err)
		}

		err = fw.ForwardPorts()
		if err != nil {
			return fmt.Errorf("port forwarder error: %v", err)
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
				fmt.Fprintf(ginkgo.GinkgoWriter, "error while forwarding port: %v\n", err)
			}
		}
	}()

	return nil
}

func (p *proxy) stop(ctx context.Context) error {
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
			return fmt.Errorf("error while forwarding port: %v", err)
		}
	}

	return nil
}
