/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	defaultTTL = 60
)

type BasicServer struct {
	// Zones is a list of DNS zones that this server should accept responses
	// for.
	Zones []string

	// Handler is an optional
	Handler dns.Handler

	// TSIG configuration options
	// EnableTSIG enables TSIG support for the DNS server
	// If true, both TSIGKeyName and TSIGKeySecret must be provided.
	EnableTSIG bool
	// TSIGKeyName to be used in responses when TSIG is enabled
	TSIGKeyName string
	// TSIGKeySecret to be used in responses when TSIG is enabled
	TSIGKeySecret string
	// TSIGZone is the DNS zone that should be used in TSIG responses
	TSIGZone string

	ctx        context.Context
	listenAddr string
	server     *dns.Server
}

// Run starts the test DNS server, binding to a random port on 127.0.0.1
func (b *BasicServer) Run(ctx context.Context) error {
	return b.RunWithAddress(ctx, "127.0.0.1:0")
}

// RunWithAddress starts the test DNS server using the specified listen address.
func (b *BasicServer) RunWithAddress(ctx context.Context, listenAddr string) error {
	log := logf.FromContext(ctx, "dnsBasicServer")

	if listenAddr == "" {
		return fmt.Errorf("listen address must be provided")
	}

	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}
	b.listenAddr = pc.LocalAddr().String()
	log = log.WithValues("address", b.listenAddr)
	log.Info("listening on UDP port")

	// update the ctx with the new logger
	ctx = logf.NewContext(ctx, log)

	b.server = &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}
	if b.EnableTSIG {
		log.Info("enabling TSIG support")
		b.server.TsigSecret = map[string]string{b.TSIGKeyName: b.TSIGKeySecret}
	}

	if b.Handler == nil {
		b.Handler = &rfc2136Handler{
			log:        log,
			txtRecords: make(map[string][]string),
			zones:      b.Zones,
			tsigZone:   b.TSIGZone,
		}
	}
	b.server.Handler = b.Handler

	// Start the DNS server in a separate goroutine and wait for it to start
	waitLock := sync.Mutex{}
	waitLock.Lock()
	b.server.NotifyStartedFunc = waitLock.Unlock
	go func() {
		log.Info("starting DNS server")
		b.server.ActivateAndServe()
		log.Info("DNS server exited")
		pc.Close()
	}()
	waitLock.Lock()
	defer waitLock.Unlock()

	return nil
}

func (b *BasicServer) ListenAddr() string {
	return b.listenAddr
}

func (b *BasicServer) Shutdown() error {
	return b.server.Shutdown()
}
