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

package util

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/portforward"
)

var (
	bindAddrOnce sync.Once
	bindAddr     string // e.g. "127.0.0.1:59432"
	bindAddrErr  error  //nolint:errname
)

// withPortForwardToBind returns the host:port address of the port-forward to the Bind
// deployment. The port-forward is started lazily on the first call and lives
// for the duration of the test process.
func withPortForwardToBind(t testing.TB, kubeClient kubernetes.Interface, restConfig *rest.Config) (string, error) {
	bindAddrOnce.Do(func() {
		bindAddr, bindAddrErr = startBindPortForward(t, kubeClient, restConfig)
	})
	return bindAddr, bindAddrErr
}

func startBindPortForward(t testing.TB, kubeClient kubernetes.Interface, restConfig *rest.Config) (string, error) {
	pods, err := kubeClient.CoreV1().Pods("bind").List(t.Context(), metav1.ListOptions{
		LabelSelector: "app=bind",
	})
	if err != nil {
		return "", fmt.Errorf("listing bind pods: %w", err)
	}

	var podName string
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			podName = pod.Name
			break
		}
	}
	if podName == "" {
		return "", fmt.Errorf("no running pod with label app=bind found in namespace 'bind'")
	}

	proxy, err := portforward.New(t.Context(), kubeClient, restConfig, "bind", podName, 8053)
	if err != nil {
		return "", fmt.Errorf("creating port-forward proxy for bind: %w", err)
	}

	if err := proxy.Start(); err != nil {
		return "", fmt.Errorf("starting port-forward proxy for bind: %w", err)
	}

	t.Logf("Started port-forward to bind at %d", proxy.LocalPort())

	// Wait for 5 seconds for the port-forward to be ready, and check that we
	// can connect to it.
	if err := wait.PollUntilContextTimeout(t.Context(), time.Second, 5*time.Second, true, func(_ context.Context) (done bool, err error) {
		err = isReady(fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
		if err != nil {
			return false, err
		}
		return true, nil
	}); err != nil {
		return "", fmt.Errorf("waiting for port-forward to be ready: %w", err)
	}

	return fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()), nil
}

func isReady(addr string) error {
	dialer := net.Dialer{Timeout: 1 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dialing TCP address %s: %w", addr, err)
	}
	defer conn.Close()

	return nil
}
