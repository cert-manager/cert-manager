package nosql

import (
	"github.com/pkg/errors"
	"github.com/smallstep/nosql/badger"
	"github.com/smallstep/nosql/bolt"
	"github.com/smallstep/nosql/database"
	"github.com/smallstep/nosql/mysql"
)

// Option is just a wrapper over database.Option.
type Option = database.Option

// DB is just a wrapper over database.DB.
type DB = database.DB

var (
	// WithValueDir is a wrapper over database.WithValueDir.
	WithValueDir = database.WithValueDir
	// WithDatabase is a wrapper over database.WithDatabase.
	WithDatabase = database.WithDatabase
	// IsErrNotFound is a wrapper over database.IsErrNotFound.
	IsErrNotFound = database.IsErrNotFound
	// IsErrOpNotSupported is a wrapper over database.IsErrOpNotSupported.
	IsErrOpNotSupported = database.IsErrOpNotSupported
)

// New returns a database with the given driver.
func New(driver, dataSourceName string, opt ...Option) (db database.DB, err error) {
	switch driver {
	case "badger":
		db = &badger.DB{}
	case "bbolt":
		db = &bolt.DB{}
	case "mysql":
		db = &mysql.DB{}
	default:
		return nil, errors.Errorf("%s database not supported", driver)
	}
	err = db.Open(dataSourceName, opt...)
	return
}
