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

package healthz

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/utils/clock"
)

const (
	// Copied from pkg/metrics/metrics.go
	healthzServerReadTimeout    = 8 * time.Second
	healthzServerWriteTimeout   = 8 * time.Second
	healthzServerMaxHeaderBytes = 1 << 20 // 1 MiB
)

// Server responds to HTTP requests to a /livez endpoint and responds with an
// error if the LeaderElector has exited or has not observed the
// LeaderElectionRecord for a given amount of time.
type Server struct {
	server *http.Server
	// LeaderHealthzAdaptor is public so that it can be retrieved by the caller
	// and used as the value for `LeaderElectionConfig.Watchdog` when
	// initializing the LeaderElector.
	LeaderHealthzAdaptor *leaderelection.HealthzAdaptor
}

// NewServer creates a new healthz.Server.
// The supplied leaderElectionHealthzAdaptorTimeout controls how long after the
// leader lease time, the leader election will be considered to have failed.
func NewServer(leaderElectionHealthzAdaptorTimeout time.Duration) *Server {
	leaderHealthzAdaptor := leaderelection.NewLeaderHealthzAdaptor(leaderElectionHealthzAdaptorTimeout)
	clockHealthAdaptor := NewClockHealthAdaptor(clock.RealClock{})
	mux := http.NewServeMux()
	healthz.InstallLivezHandler(mux, leaderHealthzAdaptor, clockHealthAdaptor)
	return &Server{
		server: &http.Server{
			ReadTimeout:    healthzServerReadTimeout,
			WriteTimeout:   healthzServerWriteTimeout,
			MaxHeaderBytes: healthzServerMaxHeaderBytes,
			Handler:        mux,
		},
		LeaderHealthzAdaptor: leaderHealthzAdaptor,
	}
}

// Start makes the server listen on the supplied socket, until the supplied
// context is cancelled, after which the server will gracefully shutdown and Start will
// exit.
// The server is given 5 seconds to shutdown gracefully.
func (o *Server) Start(ctx context.Context, l net.Listener) error {
	var g errgroup.Group
	g.Go(func() error {
		if err := o.server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-ctx.Done()
		// allow a timeout for graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// nolint: contextcheck
		return o.server.Shutdown(shutdownCtx)
	})
	return g.Wait()
}
