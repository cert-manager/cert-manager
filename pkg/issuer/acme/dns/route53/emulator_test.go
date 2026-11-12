/*
Copyright 2026 The cert-manager Authors.

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

package route53

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// The tests in this file run the Route 53 provider against AWS Emulator
// (https://github.com/aws/aws-emulator), a local program published by AWS that
// serves the AWS APIs and keeps the resources in memory.
//
// Unlike the tests in route53_test.go, which replay canned XML, these tests
// build the provider with NewDNSProviderFromOptions, sign real requests and
// read the records back to check what the provider did.
//
// `make test` downloads the emulator and sets AWS_EMULATOR to its path.
// Without that variable, the tests look for `aws-emulator` on the PATH and are
// skipped if it is not there. AWS publishes the emulator for Linux only.
// See https://docs.aws.amazon.com/emulator/latest/userguide/getting-started-linux.html

// startEmulator starts an AWS Emulator which is stopped when the test ends.
// It sets the environment variables which make the AWS SDK use the emulator,
// so the provider under test needs no test-only endpoint or HTTP client.
func startEmulator(t *testing.T) {
	t.Helper()

	// The Makefile sets AWS_EMULATOR, so that the tests cannot be skipped by
	// accident in CI.
	bin := os.Getenv("AWS_EMULATOR")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("aws-emulator"); err != nil {
			t.Skip("AWS_EMULATOR is not set and aws-emulator is not on the PATH")
		}
	}

	cmd := exec.CommandContext(t.Context(), bin, "--port=0", "--telemetry=off", "--idle-timeout=300")
	// The emulator writes its credentials and its CA certificate below $HOME.
	cmd.Env = append(cmd.Environ(), "HOME="+t.TempDir())
	// SIGTERM lets the emulator delete those files before it exits.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Wait() })

	// The emulator logs JSON lines. The line with this message is its
	// documented way to report where it listens and which files it wrote.
	// https://docs.aws.amazon.com/emulator/latest/userguide/cli-reference.html
	type serverInfo struct {
		Message     string `json:"message"`
		EndpointURL string `json:"endpoint_url"`
		ConfigFile  string `json:"config_file"`
		CAFile      string `json:"ca_file"`
	}
	started := make(chan serverInfo, 1)
	go func() {
		defer close(started)
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			var line struct {
				Fields serverInfo `json:"fields"`
			}
			if json.Unmarshal(lines.Bytes(), &line) == nil && line.Fields.Message == "emulator server information" {
				started <- line.Fields
			}
		}
	}()

	var info serverInfo
	select {
	case info = <-started:
		require.NotEmpty(t, info.EndpointURL, "aws-emulator exited before it reported its endpoint")
	case <-time.After(30 * time.Second):
		require.FailNow(t, "timed out waiting for aws-emulator to start")
	}

	for name, value := range map[string]string{
		"AWS_ENDPOINT_URL":            info.EndpointURL,
		"AWS_CA_BUNDLE":               info.CAFile,
		"AWS_CONFIG_FILE":             info.ConfigFile,
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(filepath.Dir(info.ConfigFile), "emulator_credentials"),
		"AWS_REGION":                  "us-east-1",
		"AWS_EC2_METADATA_DISABLED":   "true",
		// The emulator rejects requests signed with any other credentials,
		// so hide the credentials of the person running the tests.
		"AWS_ACCESS_KEY_ID":     "",
		"AWS_SECRET_ACCESS_KEY": "",
		"AWS_SESSION_TOKEN":     "",
		"AWS_PROFILE":           "",
	} {
		t.Setenv(name, value)
	}
}

// zoneResolver answers the "which zone holds this name?" question without DNS.
// The emulator serves the Route 53 API but it is not a DNS server.
type zoneResolver struct {
	util.Resolver
	zone string
}

func (r zoneResolver) FindZoneByFQDN(context.Context, string, []string) (string, error) {
	return r.zone, nil
}

// txtValues returns the values of all the TXT records with the given name.
func txtValues(ctx context.Context, t *testing.T, client *route53.Client, zoneID *string, fqdn string) []string {
	t.Helper()
	out, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{HostedZoneId: zoneID})
	require.NoError(t, err)
	var values []string
	for _, set := range out.ResourceRecordSets {
		if set.Type == route53types.RRTypeTxt && aws.ToString(set.Name) == fqdn {
			for _, record := range set.ResourceRecords {
				values = append(values, aws.ToString(record.Value))
			}
		}
	}
	return values
}

// createRole creates an IAM role which any identity in the emulator's account
// may assume, and returns its ARN.
// It sends the IAM request by hand so that the tests need no IAM client module.
func createRole(ctx context.Context, t *testing.T, cfg aws.Config, name string) string {
	t.Helper()
	const account = "000000000000" // The emulator has this one account.
	body := url.Values{
		"Action":   {"CreateRole"},
		"Version":  {"2010-05-08"},
		"RoleName": {name},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Principal":{"AWS":"arn:aws:iam::` + account + `:root"},"Action":"sts:AssumeRole"}]}`},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, aws.ToString(cfg.BaseEndpoint), strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	creds, err := cfg.Credentials.Retrieve(ctx)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte(body))
	require.NoError(t, v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(hash[:]), "iam", cfg.Region, time.Now()))

	resp, err := cfg.HTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRole: %s", respBody)
	return "arn:aws:iam::" + account + ":role/" + name
}

func TestEmulator(t *testing.T) {
	startEmulator(t)
	_, ctx := ktesting.NewTestContext(t)

	cfg, err := config.LoadDefaultConfig(ctx)
	require.NoError(t, err)
	admin := route53.NewFromConfig(cfg)

	// createZone creates a hosted zone and returns its ID.
	createZone := func(t *testing.T, name string) *string {
		t.Helper()
		out, err := admin.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
			Name:            aws.String(name),
			CallerReference: aws.String(t.Name()),
		})
		require.NoError(t, err)
		return out.HostedZone.Id
	}

	options := func(zone string, extra ...DNSProviderOption) []DNSProviderOption {
		return append([]DNSProviderOption{
			Nameservers{"unused.invalid:53"},
			Resolver(zoneResolver{zone: zone}),
			UserAgent("cert-manager-test"),
		}, extra...)
	}

	// Each subtest uses its own zone, so they can share the emulator and run
	// in parallel. Every Present or CleanUp takes about four seconds because
	// the record change is PENDING when the provider first asks.

	t.Run("ambient credentials: Present and CleanUp change the TXT records", func(t *testing.T) {
		t.Parallel()
		const zone, fqdn = "ambient.example.", "_acme-challenge.ambient.example."
		zoneID := createZone(t, zone)

		provider, err := NewDNSProviderFromOptions(ctx, options(zone, Ambient(true))...)
		require.NoError(t, err)

		// A certificate for example.com and *.example.com has two challenges
		// with the same record name and different values.
		require.NoError(t, provider.Present(ctx, "ambient.example", fqdn, "token-1"))
		require.NoError(t, provider.Present(ctx, "ambient.example", fqdn, "token-2"))
		require.NoError(t, provider.Present(ctx, "ambient.example", fqdn, "token-2"), "Present should succeed when the record exists")
		assert.ElementsMatch(t, []string{`"token-1"`, `"token-2"`}, txtValues(ctx, t, admin, zoneID, fqdn))

		require.NoError(t, provider.CleanUp(ctx, "ambient.example", fqdn, "token-1"))
		assert.Equal(t, []string{`"token-2"`}, txtValues(ctx, t, admin, zoneID, fqdn))

		require.NoError(t, provider.CleanUp(ctx, "ambient.example", fqdn, "token-2"))
		require.NoError(t, provider.CleanUp(ctx, "ambient.example", fqdn, "token-2"), "CleanUp should succeed when the record is gone")
		assert.Empty(t, txtValues(ctx, t, admin, zoneID, fqdn))
	})

	t.Run("access key: Present creates the TXT record", func(t *testing.T) {
		t.Parallel()
		const zone, fqdn = "static.example.", "_acme-challenge.static.example."
		zoneID := createZone(t, zone)
		creds, err := cfg.Credentials.Retrieve(ctx)
		require.NoError(t, err)

		provider, err := NewDNSProviderFromOptions(ctx, options(zone,
			AccessKeyID(creds.AccessKeyID),
			SecretAccessKey(creds.SecretAccessKey),
			Region("us-east-1"),
		)...)
		require.NoError(t, err)

		require.NoError(t, provider.Present(ctx, "static.example", fqdn, "token"))
		assert.Equal(t, []string{`"token"`}, txtValues(ctx, t, admin, zoneID, fqdn))
	})

	t.Run("wrong secret access key: Present fails", func(t *testing.T) {
		t.Parallel()
		const zone, fqdn = "wrong-secret.example.", "_acme-challenge.wrong-secret.example."
		zoneID := createZone(t, zone)
		creds, err := cfg.Credentials.Retrieve(ctx)
		require.NoError(t, err)

		provider, err := NewDNSProviderFromOptions(ctx, options(zone,
			AccessKeyID(creds.AccessKeyID),
			SecretAccessKey("wrong"),
			Region("us-east-1"),
		)...)
		require.NoError(t, err)

		assert.ErrorContains(t, provider.Present(ctx, "wrong-secret.example", fqdn, "token"), "SignatureDoesNotMatch")
		assert.Empty(t, txtValues(ctx, t, admin, zoneID, fqdn))
	})

	t.Run("role: Present creates the TXT record with the role's credentials", func(t *testing.T) {
		t.Parallel()
		const zone, fqdn = "role.example.", "_acme-challenge.role.example."
		zoneID := createZone(t, zone)
		role := createRole(ctx, t, cfg, "cert-manager")

		provider, err := NewDNSProviderFromOptions(ctx, options(zone, Ambient(true), Role(role))...)
		require.NoError(t, err)

		creds, err := provider.client.Options().Credentials.Retrieve(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, creds.SessionToken, "the provider should use the temporary credentials of the role")

		require.NoError(t, provider.Present(ctx, "role.example", fqdn, "token"))
		assert.Equal(t, []string{`"token"`}, txtValues(ctx, t, admin, zoneID, fqdn))
	})

	t.Run("role which does not exist: Present fails", func(t *testing.T) {
		t.Parallel()
		const zone, fqdn = "no-role.example.", "_acme-challenge.no-role.example."
		zoneID := createZone(t, zone)

		// The provider assumes the role when it is created.
		// Call Present too, so that this test does not depend on that.
		provider, err := NewDNSProviderFromOptions(ctx, options(zone,
			Ambient(true),
			Role("arn:aws:iam::000000000000:role/does-not-exist"),
		)...)
		if err == nil {
			err = provider.Present(ctx, "no-role.example", fqdn, "token")
		}
		assert.ErrorContains(t, err, "AssumeRole")
		assert.ErrorContains(t, err, "AccessDenied")
		assert.Empty(t, txtValues(ctx, t, admin, zoneID, fqdn))
	})

	t.Run("no hosted zone: Present fails", func(t *testing.T) {
		t.Parallel()
		const zone, fqdn = "missing.example.", "_acme-challenge.missing.example."

		provider, err := NewDNSProviderFromOptions(ctx, options(zone, Ambient(true))...)
		require.NoError(t, err)

		assert.ErrorContains(t, provider.Present(ctx, "missing.example", fqdn, "token"), "not found in Route 53")
	})
}
