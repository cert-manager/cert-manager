package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetRenewalInfo(t *testing.T) {
	var gotPath string
	suggestedStart := time.Now().Add(1 * time.Hour).UTC()
	suggestedEnd := time.Now().Add(2 * time.Hour).UTC()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := fmt.Sprintf("https://%s", r.Context().Value(http.LocalAddrContextKey))
		switch {
		case r.URL.Path == "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"newNonce":    baseURL + "/nonce",
				"newAccount":  baseURL + "/acct",
				"newOrder":    baseURL + "/new-order",
				"revokeCert":  baseURL + "/revoke",
				"keyChange":   baseURL + "/key-change",
				"renewalInfo": baseURL + "/renewalInfo",
				"meta":        map[string]any{},
			})
		case strings.HasPrefix(r.URL.Path, "/renewalInfo/"):
			gotPath = r.URL.Path
			w.Header().Set("Retry-After", "3600")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"suggestedWindow": map[string]any{
					"start": suggestedStart,
					"end":   suggestedEnd,
				},
				"explanationURL": "https://example.test/explain",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		Key:          key,
		HTTPClient:   srv.Client(),
		DirectoryURL: srv.URL + "/directory",
	}

	cert := &x509.Certificate{
		AuthorityKeyId: []byte{0xAA, 0xBB, 0xCC},
		SerialNumber:   big.NewInt(42),
	}

	ri, err := c.GetRenewalInfo(context.Background(), cert)
	if err != nil {
		t.Fatalf("GetRenewalInfo error: %v", err)
	}
	if ri.RetryAfter != time.Hour {
		t.Fatalf("expected RetryAfter=1h, got %v", ri.RetryAfter)
	}

	if gotPath == "" || !strings.HasPrefix(gotPath, "/renewalInfo/") {
		t.Fatalf("expected renewalInfo path, got %q", gotPath)
	}

	if ri.SuggestedWindow.Start != suggestedStart || ri.SuggestedWindow.End != suggestedEnd {
		t.Fatalf("expected suggestedWindow start=%s end=%s, got start=%s end=%s", suggestedStart, suggestedEnd, ri.SuggestedWindow.Start, ri.SuggestedWindow.End)
	}
}

func TestGetRenewalInfo_Errors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dirHandler := func(renewalInfoURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"newNonce":   "nonce",
				"newAccount": "acct",
				"newOrder":   "new-order",
				"revokeCert": "revoke",
				"keyChange":  "key-change",
				"meta":       map[string]any{},
			}
			if renewalInfoURL != "" {
				resp["renewalInfo"] = renewalInfoURL
			}
			err = json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("failed to write directory response: %v", err)
			}
		}
	}

	t.Run("nil certificate", func(t *testing.T) {
		c := &Client{Key: key, HTTPClient: http.DefaultClient, DirectoryURL: "http://127.0.0.1/directory"}
		_, err := c.GetRenewalInfo(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil certificate")
		}
	})

	t.Run("CA does not support ARI", func(t *testing.T) {
		srv := httptest.NewTLSServer(dirHandler(""))
		defer srv.Close()
		c := &Client{Key: key, HTTPClient: srv.Client(), DirectoryURL: srv.URL + "/directory"}
		cert := &x509.Certificate{AuthorityKeyId: []byte{0xAA}, SerialNumber: big.NewInt(1)}
		_, err := c.GetRenewalInfo(context.Background(), cert)
		if err == nil || !strings.Contains(err.Error(), "does not support ARI") {
			t.Fatalf("expected ARI not supported error, got %v", err)
		}
	})

	t.Run("malformed JSON response", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			baseURL := fmt.Sprintf("https://%s", r.Context().Value(http.LocalAddrContextKey))

			if r.URL.Path == "/directory" {
				dirHandler(baseURL+"/renewalInfo")(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not-json"))
		}))
		defer srv.Close()
		c := &Client{Key: key, HTTPClient: srv.Client(), DirectoryURL: srv.URL + "/directory"}
		cert := &x509.Certificate{AuthorityKeyId: []byte{0xAA}, SerialNumber: big.NewInt(1)}
		_, err := c.GetRenewalInfo(context.Background(), cert)
		if err == nil || !strings.Contains(err.Error(), "invalid renewalInfo response") {
			t.Fatalf("expected invalid renewalInfo response error, got %v", err)
		}
	})

	t.Run("invalid suggestedWindow (start after end)", func(t *testing.T) {
		suggestedStart := time.Now().Add(2 * time.Hour).UTC()
		suggestedEnd := time.Now().Add(1 * time.Hour).UTC()
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			baseURL := fmt.Sprintf("https://%s", r.Context().Value(http.LocalAddrContextKey))

			if r.URL.Path == "/directory" {
				dirHandler(baseURL+"/renewalInfo")(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"suggestedWindow": map[string]any{
					"start": suggestedStart,
					"end":   suggestedEnd,
				},
				"explanationURL": "https://example.test/explain",
			})
		}))
		defer srv.Close()
		c := &Client{Key: key, HTTPClient: srv.Client(), DirectoryURL: srv.URL + "/directory"}
		cert := &x509.Certificate{AuthorityKeyId: []byte{0xAA}, SerialNumber: big.NewInt(1)}
		_, err := c.GetRenewalInfo(context.Background(), cert)
		if err == nil || !strings.Contains(err.Error(), "invalid suggestedWindow") {
			t.Fatalf("expected invalid suggestedWindow error, got %v", err)
		}
	})
}
