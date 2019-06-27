package authority

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"
)

const legacyAuthority = "step-certificate-authority"

// Authority implements the Certificate Authority internal interface.
type Authority struct {
	config               *Config
	rootX509Certs        []*x509.Certificate
	intermediateIdentity *x509util.Identity
	validateOnce         bool
	certificates         *sync.Map
	startTime            time.Time
	provisioners         *provisioner.Collection
	db                   db.AuthDB
	// Do not re-initialize
	initOnce bool
}

// Option sets options to the Authority.
type Option func(*Authority)

// WithDatabase sets an already initialized authority database to a new
// authority. This option is intended to be use on graceful reloads.
func WithDatabase(db db.AuthDB) Option {
	return func(a *Authority) {
		a.db = db
	}
}

// New creates and initiates a new Authority type.
func New(config *Config, opts ...Option) (*Authority, error) {
	err := config.Validate()
	if err != nil {
		return nil, err
	}

	var a = &Authority{
		config:       config,
		certificates: new(sync.Map),
		provisioners: provisioner.NewCollection(config.getAudiences()),
	}
	for _, opt := range opts {
		opt(a)
	}
	if err := a.init(); err != nil {
		return nil, err
	}
	return a, nil
}

// init performs validation and initializes the fields of an Authority struct.
func (a *Authority) init() error {
	// Check if handler has already been validated/initialized.
	if a.initOnce {
		return nil
	}

	var err error
	// Initialize step-ca Database if it's not already initialized with WithDB.
	// If a.config.DB is nil then a simple, barebones in memory DB will be used.
	if a.db == nil {
		if a.db, err = db.New(a.config.DB); err != nil {
			return err
		}
	}

	// Load the root certificates and add them to the certificate store
	a.rootX509Certs = make([]*x509.Certificate, len(a.config.Root))
	for i, path := range a.config.Root {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		// Add root certificate to the certificate map
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
		a.rootX509Certs[i] = crt
	}

	// Add federated roots
	for _, path := range a.config.FederatedRoots {
		crt, err := pemutil.ReadCertificate(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(crt.Raw)
		a.certificates.Store(hex.EncodeToString(sum[:]), crt)
	}

	// Decrypt and load intermediate public / private key pair.
	if len(a.config.Password) > 0 {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(
			a.config.IntermediateCert,
			a.config.IntermediateKey,
			pemutil.WithPassword([]byte(a.config.Password)),
		)
		if err != nil {
			return err
		}
	} else {
		a.intermediateIdentity, err = x509util.LoadIdentityFromDisk(a.config.IntermediateCert, a.config.IntermediateKey)
		if err != nil {
			return err
		}
	}

	// Store all the provisioners
	for _, p := range a.config.AuthorityConfig.Provisioners {
		if err := a.provisioners.Store(p); err != nil {
			return err
		}
	}

	// JWT numeric dates are seconds.
	a.startTime = time.Now().Truncate(time.Second)
	// Set flag indicating that initialization has been completed, and should
	// not be repeated.
	a.initOnce = true

	return nil
}

// GetDatabase returns the authority database. If the configuration does not
// define a database, GetDatabase will return a db.SimpleDB instance.
func (a *Authority) GetDatabase() db.AuthDB {
	return a.db
}

// Shutdown safely shuts down any clients, databases, etc. held by the Authority.
func (a *Authority) Shutdown() error {
	return a.db.Shutdown()
}
