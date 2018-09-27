package grpc

import (
	"crypto/tls"
	"time"

	pb "github.com/jetstack/cert-manager-proto"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type provider struct {
	service  string
	do       grpc.DialOption
	timeout  time.Duration
	interval time.Duration
}

func NewDNSProviderTLS(service, serverName string, clientCert *tls.Certificate, timeout, interval time.Duration) (*provider, error) {
	tc := &tls.Config{
		ServerName: serverName,
	}
	if clientCert != nil {
		tc.Certificates = []tls.Certificate{*clientCert}
	}
	do := grpc.WithTransportCredentials(credentials.NewTLS(tc))
	return &provider{service, do, timeout, interval}, nil
}

func NewDNSProviderInsecure(service string, timeout, interval time.Duration) (*provider, error) {
	do := grpc.WithInsecure()
	return &provider{service, do, timeout, interval}, nil
}

func (p *provider) Present(domain, token, key string) error {
	fqdn, value, ttl, err := util.DNS01Record(domain, key, util.RecursiveNameservers)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.interval)
	defer cancel()
	conn, err := grpc.DialContext(ctx, p.service, p.do)
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewAcmeDnsSolverServiceClient(conn)
	r := &pb.PresentRequest{
		Fqdn:  fqdn,
		Value: value,
		Ttl:   uint32(ttl),
	}
	_, err = c.Present(ctx, r)
	if err != nil {
		return err
	}
	return nil
}

func (p *provider) CleanUp(domain, token, key string) error {
	fqdn, _, _, err := util.DNS01Record(domain, key, util.RecursiveNameservers)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.interval)
	defer cancel()
	conn, err := grpc.DialContext(ctx, p.service, p.do)
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewAcmeDnsSolverServiceClient(conn)
	r := &pb.CleanUpRequest{
		Fqdn: fqdn,
	}
	_, err = c.CleanUp(ctx, r)
	if err != nil {
		return err
	}
	return nil
}

func (c *provider) Timeout() (timeout, interval time.Duration) {
	return c.timeout, c.interval
}
