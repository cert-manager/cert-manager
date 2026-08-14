package pki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"hegel.dev/go/hegel"
)

// Probe: bundles containing a cross-signed intermediate (same subject and
// key, signed by two different roots), as served by real CAs. Property:
// whatever ParseSingleCertificateChainPEM does with such a bundle, the
// outcome must not depend on the order of certificates in the input.
func TestParseChainCrossSignDeterminism(t *testing.T) {
	root1 := mustCreateBundle(t, nil, "root1")
	root2 := mustCreateBundle(t, nil, "root2")

	ipk, err := GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	itmpl := func() *x509.Certificate {
		return &x509.Certificate{
			BasicConstraintsValid: true,
			PublicKeyAlgorithm:    x509.ECDSA,
			PublicKey:             ipk.Public(),
			IsCA:                  true,
			Subject:               pkix.Name{CommonName: "cross-int"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Minute),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
	}
	intPEM1, intCert1, err := SignCertificate(itmpl(), root1.cert, ipk.Public(), root1.pk)
	if err != nil {
		t.Fatal(err)
	}
	intPEM2, intCert2, err := SignCertificate(itmpl(), root2.cert, ipk.Public(), root2.pk)
	if err != nil {
		t.Fatal(err)
	}
	intV1 := &testBundle{cert: intCert1, pem: intPEM1, pk: ipk}
	intV2 := &testBundle{cert: intCert2, pem: intPEM2, pk: ipk}
	leaf := mustCreateBundle(t, intV1, "leaf")

	hegel.Test(t, func(ht *hegel.T) {
		certs := []*testBundle{leaf, intV1, intV2}
		if hegel.Draw(ht, hegel.Booleans()) {
			certs = append(certs, root1)
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			certs = append(certs, root2)
		}

		join := func(bs []*testBundle) []byte {
			var out []byte
			for _, b := range bs {
				out = append(out, b.pem...)
			}
			return out
		}
		canonical, canonicalErr := ParseSingleCertificateChainPEM(join(certs))
		shuffled, shuffledErr := ParseSingleCertificateChainPEM(join(drawShuffle(ht, certs)))

		ht.Logf("canonical outcome: err=%v chainLen=%d caLen=%d", canonicalErr, len(canonical.ChainPEM), len(canonical.CAPEM))
		if (canonicalErr == nil) != (shuffledErr == nil) {
			ht.Fatalf("order-dependent outcome: canonical err=%v, shuffled err=%v (certs=%d)", canonicalErr, shuffledErr, len(certs))
		}
		if !bytes.Equal(canonical.ChainPEM, shuffled.ChainPEM) || !bytes.Equal(canonical.CAPEM, shuffled.CAPEM) {
			ht.Fatalf("order-dependent bundle:\ncanonical chain:\n%s\nshuffled chain:\n%s\ncanonical CA:\n%s\nshuffled CA:\n%s",
				canonical.ChainPEM, shuffled.ChainPEM, canonical.CAPEM, shuffled.CAPEM)
		}
	}, hegel.WithTestCases(300))
}
