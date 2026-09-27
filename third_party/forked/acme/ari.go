package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (c *Client) GetRenewalInfo(ctx context.Context, cert *x509.Certificate) (*RenewalInfoResponse, error) {
	certID, err := CertificateARIID(cert)
	if err != nil {
		return nil, err
	}

	return c.getRenewalInfoFromCertARIID(ctx, certID)
}

func (c *Client) getRenewalInfoFromCertARIID(ctx context.Context, ariID string) (*RenewalInfoResponse, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}
	if c.dir == nil || c.dir.RenewalInfo == "" {
		return nil, ErrCADoesNotSupportARI
	}

	base := strings.TrimRight(c.dir.RenewalInfo, "/")
	u := base + "/" + strings.TrimLeft(ariID, "/")

	res, err := c.get(ctx, u, wantStatus(http.StatusOK))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var ri RenewalInfoResponse
	if err := json.NewDecoder(res.Body).Decode(&ri); err != nil {
		return nil, fmt.Errorf("acme: invalid renewalInfo response: %w", err)
	}

	ri.RetryAfter = retryAfter(res.Header.Get("Retry-After"))

	// Basic sanity check: window must be well-formed.
	if !ri.SuggestedWindow.Start.IsZero() && !ri.SuggestedWindow.End.IsZero() {
		if !ri.SuggestedWindow.Start.Before(ri.SuggestedWindow.End) {
			return nil, fmt.Errorf("acme: invalid suggestedWindow: start must be before end")
		}
	}
	return &ri, nil
}
