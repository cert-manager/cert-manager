package provisioner

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
)

// DefaultProvisionersLimit is the default limit for listing provisioners.
const DefaultProvisionersLimit = 20

// DefaultProvisionersMax is the maximum limit for listing provisioners.
const DefaultProvisionersMax = 100

type uidProvisioner struct {
	provisioner Interface
	uid         string
}

type provisionerSlice []uidProvisioner

func (p provisionerSlice) Len() int           { return len(p) }
func (p provisionerSlice) Less(i, j int) bool { return p[i].uid < p[j].uid }
func (p provisionerSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// loadByTokenPayload is a payload used to extract the id used to load the
// provisioner.
type loadByTokenPayload struct {
	jose.Claims
	AuthorizedParty string `json:"azp"` // OIDC client id
	TenantID        string `json:"tid"` // Microsoft Azure tenant id
}

// Collection is a memory map of provisioners.
type Collection struct {
	byID      *sync.Map
	byKey     *sync.Map
	sorted    provisionerSlice
	audiences Audiences
}

// NewCollection initializes a collection of provisioners. The given list of
// audiences are the audiences used by the JWT provisioner.
func NewCollection(audiences Audiences) *Collection {
	return &Collection{
		byID:      new(sync.Map),
		byKey:     new(sync.Map),
		audiences: audiences,
	}
}

// Load a provisioner by the ID.
func (c *Collection) Load(id string) (Interface, bool) {
	return loadProvisioner(c.byID, id)
}

// LoadByToken parses the token claims and loads the provisioner associated.
func (c *Collection) LoadByToken(token *jose.JSONWebToken, claims *jose.Claims) (Interface, bool) {
	var audiences []string
	// Get all audiences with the given fragment
	fragment := extractFragment(claims.Audience)
	if fragment == "" {
		audiences = c.audiences.All()
	} else {
		audiences = c.audiences.WithFragment(fragment).All()
	}

	// match with server audiences
	if matchesAudience(claims.Audience, audiences) {
		// Use fragment to get provisioner name (GCP, AWS)
		if fragment != "" {
			return c.Load(fragment)
		}
		// If matches with stored audiences it will be a JWT token (default), and
		// the id would be <issuer>:<kid>.
		return c.Load(claims.Issuer + ":" + token.Headers[0].KeyID)
	}

	// The ID will be just the clientID stored in azp, aud or tid.
	var payload loadByTokenPayload
	if err := token.UnsafeClaimsWithoutVerification(&payload); err != nil {
		return nil, false
	}
	// Audience is required
	if len(payload.Audience) == 0 {
		return nil, false
	}
	// Try with azp (OIDC)
	if len(payload.AuthorizedParty) > 0 {
		if p, ok := c.Load(payload.AuthorizedParty); ok {
			return p, ok
		}
	}
	// Try with tid (Azure)
	if payload.TenantID != "" {
		if p, ok := c.Load(payload.TenantID); ok {
			return p, ok
		}
	}
	// Fallback to aud
	return c.Load(payload.Audience[0])
}

// LoadByCertificate looks for the provisioner extension and extracts the
// proper id to load the provisioner.
func (c *Collection) LoadByCertificate(cert *x509.Certificate) (Interface, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(stepOIDProvisioner) {
			var provisioner stepProvisionerASN1
			if _, err := asn1.Unmarshal(e.Value, &provisioner); err != nil {
				return nil, false
			}
			switch Type(provisioner.Type) {
			case TypeJWK:
				return c.Load(string(provisioner.Name) + ":" + string(provisioner.CredentialID))
			case TypeAWS:
				return c.Load("aws/" + string(provisioner.Name))
			case TypeGCP:
				return c.Load("gcp/" + string(provisioner.Name))
			default:
				return c.Load(string(provisioner.CredentialID))
			}
		}
	}

	// Default to noop provisioner if an extension is not found. This allows to
	// accept a renewal of a cert without the provisioner extension.
	return &noop{}, true
}

// LoadEncryptedKey returns an encrypted key by indexed by KeyID. At this moment
// only JWK encrypted keys are indexed by KeyID.
func (c *Collection) LoadEncryptedKey(keyID string) (string, bool) {
	p, ok := loadProvisioner(c.byKey, keyID)
	if !ok {
		return "", false
	}
	_, key, ok := p.GetEncryptedKey()
	return key, ok
}

// Store adds a provisioner to the collection and enforces the uniqueness of
// provisioner IDs.
func (c *Collection) Store(p Interface) error {
	// Store provisioner always in byID. ID must be unique.
	if _, loaded := c.byID.LoadOrStore(p.GetID(), p); loaded == true {
		return errors.New("cannot add multiple provisioners with the same id")
	}

	// Store provisioner in byKey if EncryptedKey is defined.
	if kid, _, ok := p.GetEncryptedKey(); ok {
		c.byKey.Store(kid, p)
	}

	// Store sorted provisioners.
	// Use the first 4 bytes (32bit) of the sum to insert the order
	// Using big endian format to get the strings sorted:
	// 0x00000000, 0x00000001, 0x00000002, ...
	bi := make([]byte, 4)
	sum := provisionerSum(p)
	binary.BigEndian.PutUint32(bi, uint32(c.sorted.Len()))
	sum[0], sum[1], sum[2], sum[3] = bi[0], bi[1], bi[2], bi[3]
	c.sorted = append(c.sorted, uidProvisioner{
		provisioner: p,
		uid:         hex.EncodeToString(sum),
	})
	sort.Sort(c.sorted)
	return nil
}

// Find implements pagination on a list of sorted provisioners.
func (c *Collection) Find(cursor string, limit int) (List, string) {
	switch {
	case limit <= 0:
		limit = DefaultProvisionersLimit
	case limit > DefaultProvisionersMax:
		limit = DefaultProvisionersMax
	}

	n := c.sorted.Len()
	cursor = fmt.Sprintf("%040s", cursor)
	i := sort.Search(n, func(i int) bool { return c.sorted[i].uid >= cursor })

	slice := List{}
	for ; i < n && len(slice) < limit; i++ {
		slice = append(slice, c.sorted[i].provisioner)
	}

	if i < n {
		return slice, strings.TrimLeft(c.sorted[i].uid, "0")
	}
	return slice, ""
}

func loadProvisioner(m *sync.Map, key string) (Interface, bool) {
	i, ok := m.Load(key)
	if !ok {
		return nil, false
	}
	p, ok := i.(Interface)
	if !ok {
		return nil, false
	}
	return p, true
}

// provisionerSum returns the SHA1 of the provisioners ID. From this we will
// create the unique and sorted id.
func provisionerSum(p Interface) []byte {
	sum := sha1.Sum([]byte(p.GetID()))
	return sum[:]
}

// matchesAudience returns true if A and B share at least one element.
func matchesAudience(as, bs []string) bool {
	if len(bs) == 0 || len(as) == 0 {
		return false
	}

	for _, b := range bs {
		for _, a := range as {
			if b == a || stripPort(a) == stripPort(b) {
				return true
			}
		}
	}
	return false
}

// stripPort attempts to strip the port from the given url. If parsing the url
// produces errors it will just return the passed argument.
func stripPort(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	u.Host = u.Hostname()
	return u.String()
}

// extractFragment extracts the first fragment of an audience url.
func extractFragment(audience []string) string {
	for _, s := range audience {
		if u, err := url.Parse(s); err == nil && u.Fragment != "" {
			return u.Fragment
		}
	}
	return ""
}
