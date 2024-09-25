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

package healthz_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/cert-manager/pkg/healthz"

	_ "k8s.io/klog/v2/ktesting/init" // add command line flags
)

const (
	localIdentity   = "local-node"
	remoteIdentity  = "remote-node"
	lockDescription = "fake-resource-lock"
)

// TestHealthzLivezLeaderElection checks the responses of the `/livez/leaderElection` endpoint.
//
// These tests are intended to demonstrate that the LeaderElectionHealthzAdaptor
// does indeed cause the `/livez` endpoint to return errors if the healthz
// server continues to run after the LeaderElector go-routine has exited.
func TestHealthzLivezLeaderElection(t *testing.T) {

	type input struct {
		leaderElectionEnabled bool
		resourceLock          *fakeResourceLock
		onNewLeaderHook       func(in *input)
	}

	type output struct {
		responseBody string
		responseCode int
	}

	type testCase struct {
		name string
		in   input
		out  output
	}

	tests := []testCase{
		{
			// OK: when leader-election is disabled (--leader-elect=false) the leader
			// election healthz adaptor always returns OK.
			//
			// LeaderElectionHealthzAdaptor.Check returns nil if its
			// LeaderElector pointer has not been set.
			// See https://github.com/kubernetes/client-go/blob/8cbca742aebe24b24f7f4e32fd999942fa9133e8/tools/leaderelection/healthzadaptor.go#L43-L52
			name: "ok-leader-election-disabled",
			in: input{
				leaderElectionEnabled: false,
			},
			out: output{
				responseBody: "ok",
				responseCode: http.StatusOK,
			},
		},
		{
			// OK: when the local node wins and holds the leader election
			name: "ok-local-leader",
			in: input{
				leaderElectionEnabled: true,
				resourceLock:          &fakeResourceLock{},
			},
			out: output{
				responseBody: "ok",
				responseCode: http.StatusOK,
			},
		},
		{
			// OK: when a remote node is leader and has updated the leader
			// election record.
			//
			// LeaderElect.Check always succeeds when another node has the
			// leader lock.
			// See https://github.com/kubernetes/client-go/blob/8cbca742aebe24b24f7f4e32fd999942fa9133e8/tools/leaderelection/leaderelection.go#L385-L399
			name: "ok-remote-leader",
			in: input{
				leaderElectionEnabled: true,
				resourceLock: &fakeResourceLock{
					record: &resourcelock.LeaderElectionRecord{
						HolderIdentity: remoteIdentity,
					},
				},
			},
			out: output{
				responseBody: "ok",
				responseCode: http.StatusOK,
			},
		},
		{
			// Failure: when update starts to fail after the local node has once
			// acquired the leader election lock.
			//
			// This is intended to simulate the situation where the
			// LeaderElector go-routine has exited, but the parent process is
			// wedged and has not exited.
			// In this situation, the /livez endpoint responds with an error,
			// because the LeaderElectionHealthzAdaptor still has a reference to
			// the no-longer running LeaderElector and its last state.
			//
			// Start LeaderElector without a LeaderElectionRecord, wait for the
			// record to be created, and then when LeaderElector calls the
			// OnNewLeader callback, set the fakeResourceLock to return an error
			// when Update is called.
			// This persistent error causes `LeaderElector.renew` to exit and
			// causes LeaderElector.Run to exit after the `RenewDeadline`.
			//
			// The LeaderElection go-routine will exit but the healthz server
			// will continue running.
			name: "fail-delayed-update-error",
			in: input{
				leaderElectionEnabled: true,
				resourceLock: &fakeResourceLock{
					record: nil,
				},
				onNewLeaderHook: func(in *input) {
					in.resourceLock.updateError = fmt.Errorf("simulated-delayed-update-error")
				},
			},
			out: output{
				responseBody: "internal server error: failed election to renew leadership on lease \n",
				responseCode: http.StatusInternalServerError,
			},
		},
		{
			// Failure: when the local node attempts to acquire the lease but fails to update
			// the leader election record.
			//
			// Like the fail-delayed-update-error test, this is intended to
			// cause the LeaderElector to exit, leaving the healthz server
			// running and querying the last state of the exited LeaderElector.
			//
			// In this simulation, there is already a LeaderElectionRecord belonging to the local node,
			// and the update is simulated to fail on the first attempt.
			//
			// TODO(wallrj): This test may be redundant because it has the same
			// effect as `fail-delayed-update-error`, in causing the running
			// LeaderElector to exit.
			name: "fail-immediate-update-error",
			in: input{
				leaderElectionEnabled: true,
				resourceLock: &fakeResourceLock{
					record: &resourcelock.LeaderElectionRecord{
						HolderIdentity: localIdentity,
					},
					updateError: fmt.Errorf("simulated-update-error"),
				},
			},
			out: output{
				responseBody: "internal server error: failed election to renew leadership on lease \n",
				responseCode: http.StatusInternalServerError,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log, ctx := ktesting.NewTestContext(t)

			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			livezURL := "http://" + l.Addr().String() + "/livez/leaderElection"

			const leaderElectionHealthzAdaptorTimeout = 0
			s := healthz.NewServer(leaderElectionHealthzAdaptorTimeout)

			g, gCTX := errgroup.WithContext(ctx)

			leaderElected := make(chan struct{})

			if tc.in.leaderElectionEnabled {
				const (
					leaseDuration = 500 * time.Millisecond
					renewDeadline = 400 * time.Millisecond
					retryPeriod   = 300 * time.Millisecond
				)

				log.Info(
					"Starting leader election go-routine",
					"leaseDuration", leaseDuration,
					"renewDeadline", renewDeadline,
					"retryPeriod", retryPeriod,
				)
				tc.in.resourceLock.lockName = t.Name()
				g.Go(func() error {
					defer log.Info("Leader election go-routine finished")
					leaderelection.RunOrDie(gCTX, leaderelection.LeaderElectionConfig{
						LeaseDuration: leaseDuration,
						RenewDeadline: renewDeadline,
						RetryPeriod:   retryPeriod,
						Callbacks: leaderelection.LeaderCallbacks{
							OnStartedLeading: func(context.Context) {
								log.Info("leaderelection.LeaderCallbacks.OnStartedLeading")
							},
							OnStoppedLeading: func() {
								log.Info("leaderelection.LeaderCallbacks.OnStoppedLeading")
							},
							OnNewLeader: func(identity string) {
								log.Info("leaderelection.LeaderCallbacks.OnNewLeader", "identity", identity)
								if tc.in.onNewLeaderHook != nil {
									tc.in.onNewLeaderHook(&tc.in)
								}
								close(leaderElected)
							},
						},
						Lock:     tc.in.resourceLock,
						WatchDog: s.LeaderHealthzAdaptor,
					})
					return nil
				})
			}

			log.Info("Starting healthz server go-routine")
			g.Go(func() error {
				defer log.Info("Healthz server go-routine finished")
				return s.Start(gCTX, l)
			})

			if tc.in.leaderElectionEnabled {
				log.Info("Waiting for a LeaderElector to know the current leader before polling liveness endpoint")
				<-leaderElected
			}

			const (
				pollingInterval = 500 * time.Millisecond
				pollingTimeout  = 3 * time.Second
			)
			log.Info(
				"Polling liveness endpoint",
				"url", livezURL,
				"interval", pollingInterval,
				"timeout", pollingTimeout,
			)
			var (
				lastResponseCode int
				lastResponseBody string
			)
			assert.Eventually(t, func() bool {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, livezURL, nil)
				require.NoError(t, err)
				resp, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				defer func() {
					require.NoError(t, resp.Body.Close())
				}()
				bodyBytes, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				lastResponseCode = resp.StatusCode
				lastResponseBody = string(bodyBytes)

				log.Info("liveness-probe", "response-code", lastResponseCode, "response-body", lastResponseBody)

				return tc.out.responseCode == lastResponseCode && tc.out.responseBody == lastResponseBody
			}, pollingTimeout, pollingInterval)

			assert.Equal(t, tc.out.responseBody, lastResponseBody)
			assert.Equal(t, tc.out.responseCode, lastResponseCode)
			cancel()
			require.NoError(t, g.Wait())
		})
	}
}

// fakeResourceLock implements resourcelock.Interface sufficiently to simulate:
// * successful acquisition of the leader election lock by the local node,
// * current possession of the leader election lock by a remote node, and
// * failures in leader election which cause the `LeaderElection.Run` function to exit.
//
// The intention is to be able to test the behavior of the
// LeaderElectionHealthzAdaptor under those circumstances.
type fakeResourceLock struct {
	lockName    string
	record      *resourcelock.LeaderElectionRecord
	getError    error
	updateError error
	lock        sync.Mutex
}

func (o *fakeResourceLock) Identity() string {
	return localIdentity
}

func (o *fakeResourceLock) Describe() string {
	return o.lockName
}

// Get returns not-found error if the leader election record is not currently
// set i.e. the zero value of fakeResourceLock,
// to simulate a situation where no leader has ever been elected.
//
// Or if there is an existing record, it simply returns it.
// This is to allow simulating the situation where the local node has won the
// election and updated the record by calling Create or subsequently Update.
//
// There is a special case, where if the holder == remote-node,
// we are simulating a remote leader.
// And in this case, we want to always return a unique []byte representation,
// which causes the leader election library to treat the leader election record
// as having been renewed.
// To do this we increment the LeaderTransitions field.
//
// This aspect of the LeaderElectionRecord API is documented as follows:
// > LeaderElectionRecord is the record that is stored in the leader election annotation.
// > This information should be used for observational purposes only and could be replaced
// > with a random string (e.g. UUID) with only slight modification of this code.
// > -- https://github.com/kubernetes/kubernetes/blob/7e25f1232a9f89875641431ae011c916f0376c57/staging/src/k8s.io/client-go/tools/leaderelection/resourcelock/interface.go#L107-L110
func (o *fakeResourceLock) Get(ctx context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	o.lock.Lock()
	defer o.lock.Unlock()

	klog.FromContext(ctx).WithName("fakeResourceLock").Info("Get")
	if o.getError != nil {
		return nil, nil, o.getError
	}
	if o.record == nil {
		err := errors.NewNotFound(schema.ParseGroupResource("configmap"), "foo")
		return nil, nil, err
	}

	// If simulating a remote-node leader, increment the LeaderTransitions field,
	// simply to ensure a unique []byte representation each time.
	// See the function documentation above for a fuller explanation.
	if o.record.HolderIdentity == remoteIdentity {
		o.record.LeaderTransitions++
	}

	lerByte, err := json.Marshal(*o.record)
	if err != nil {
		return nil, nil, err
	}
	return o.record, lerByte, nil
}

func (o *fakeResourceLock) Create(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	o.lock.Lock()
	defer o.lock.Unlock()

	klog.FromContext(ctx).WithName("fakeResourceLock").Info("Create")
	o.record = &ler
	return nil
}

func (o *fakeResourceLock) Update(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	o.lock.Lock()
	defer o.lock.Unlock()

	klog.FromContext(ctx).WithName("fakeResourceLock").Info("Update")
	o.record = &ler
	return o.updateError
}

func (o *fakeResourceLock) RecordEvent(_ string) {}

var _ resourcelock.Interface = &fakeResourceLock{}
