package x509util

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/errs"
)

// Fingerprint returns the SHA-256 fingerprint of the certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

// SplitSANs splits a slice of Subject Alternative Names into slices of
// IP Addresses and DNS Names. If an element is not an IP address, then it
// is bucketed as a DNS Name.
func SplitSANs(sans []string) (dnsNames []string, ips []net.IP) {
	dnsNames = []string{}
	ips = []net.IP{}
	if sans == nil {
		return
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			// If not IP then assume DNSName.
			dnsNames = append(dnsNames, san)
		}
	}
	return
}

// ReadCertPool loads a certificate pool from disk.
// *path*: a file, a directory, or a comma-separated list of files.
func ReadCertPool(path string) (*x509.CertPool, error) {
	info, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "os.Stat %s failed", path)
	}

	var (
		files []string
		pool  = x509.NewCertPool()
	)
	if info != nil && info.IsDir() {
		finfos, err := ioutil.ReadDir(path)
		if err != nil {
			return nil, errs.FileError(err, path)
		}
		for _, finfo := range finfos {
			files = append(files, filepath.Join(path, finfo.Name()))
		}
	} else {
		files = strings.Split(path, ",")
		for i := range files {
			files[i] = strings.TrimSpace(files[i])
		}
	}

	var pems []byte
	for _, f := range files {
		bytes, err := ioutil.ReadFile(f)
		if err != nil {
			return nil, errs.FileError(err, f)
		}
		for len(bytes) > 0 {
			var block *pem.Block
			block, bytes = pem.Decode(bytes)
			if block == nil {
				// TODO: at a higher log level we should log the file we could not find.
				break
			}
			// Ignore PEM blocks that are not CERTIFICATEs.
			if block.Type != "CERTIFICATE" {
				continue
			}
			pems = append(pems, pem.EncodeToMemory(block)...)
		}
	}
	if ok := pool.AppendCertsFromPEM(pems); !ok {
		return nil, errors.Errorf("error loading Root certificates")
	}
	return pool, nil
}
