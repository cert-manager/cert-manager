package database

import (
	"fmt"

	"errors"
)

var (
	// ErrNotFound is the type returned on DB implementations if an item does not
	// exist.
	ErrNotFound = errors.New("not found")
	// ErrOpNotSupported is the type returned on DB implementations if an operation
	// is not supported.
	ErrOpNotSupported = errors.New("operation not supported")
)

// IsErrNotFound returns true if the cause of the given error is ErrNotFound.
func IsErrNotFound(err error) bool {
	return err == ErrNotFound || cause(err) == ErrNotFound
}

// IsErrOpNotSupported returns true if the cause of the given error is ErrOpNotSupported.
func IsErrOpNotSupported(err error) bool {
	return err == ErrOpNotSupported || cause(err) == ErrNotFound
}

// cause (from github.com/pkg/errors) returns the underlying cause of the
// error, if possible. An error value has a cause if it implements the
// following interface:
//
//     type causer interface {
//            Cause() error
//     }
//
// If the error does not implement Cause, the original error will
// be returned. If the error is nil, nil will be returned without further
// investigation.
func cause(err error) error {
	type causer interface {
		Cause() error
	}

	for err != nil {
		cause, ok := err.(causer)
		if !ok {
			break
		}
		err = cause.Cause()
	}
	return err
}

// Options are configuration options for the database.
type Options struct {
	Database string
	ValueDir string
}

// Option is the modifier type over Options.
type Option func(o *Options) error

// WithValueDir is a modifier that sets the ValueDir attribute of Options.
func WithValueDir(path string) Option {
	return func(o *Options) error {
		o.ValueDir = path
		return nil
	}
}

// WithDatabase is a modifier that sets the Database attribute of Options.
func WithDatabase(db string) Option {
	return func(o *Options) error {
		o.Database = db
		return nil
	}
}

// DB is a interface to be implemented by the databases.
type DB interface {
	// Open opens the database available with the given options.
	Open(dataSourceName string, opt ...Option) error
	// Close closes the current database.
	Close() error
	// Get returns the value stored in the given table/bucket and key.
	Get(bucket, key []byte) (ret []byte, err error)
	// Set sets the given value in the given table/bucket and key.
	Set(bucket, key, value []byte) error
	// CmpAndSwap swaps the value at the given bucket and key if the current
	// value is equivalent to the oldValue input. Returns 'true' if the
	// swap was successful and 'false' otherwise.
	CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error)
	// Del deletes the data in the given table/bucket and key.
	Del(bucket, key []byte) error
	// List returns a list of all the entries in a given table/bucket.
	List(bucket []byte) ([]*Entry, error)
	// Update performs a transaction with multiple read-write commands.
	Update(tx *Tx) error
	// CreateTable creates a table or a bucket in the database.
	CreateTable(bucket []byte) error
	// DeleteTable deletes a table or a bucket in the database.
	DeleteTable(bucket []byte) error
}

// TxCmd is the type used to represent database command and operations.
type TxCmd int

const (
	// CreateTable on a TxEntry will represent the creation of a table or
	// bucket on the database.
	CreateTable TxCmd = iota
	// DeleteTable on a TxEntry will represent the deletion of a table or
	// bucket on the database.
	DeleteTable
	// Get on a TxEntry will represent a command to retrieve data from the
	// database.
	Get
	// Set on a TxEntry will represent a command to write data on the
	// database.
	Set
	// Delete on a TxEntry represent a command to delete data on the database.
	Delete
	// CmpAndSwap on a TxEntry will represent a compare and swap operation on
	// the database. It will compare the value read and change it if it's
	// different. The TxEntry will contain the value read.
	CmpAndSwap
	// CmpOrRollback on a TxEntry will represent a read transaction that will
	// compare the values will the ones passed, and if they don't match the
	// transaction will fail
	CmpOrRollback
)

// String implements the fmt.Stringer interface on TxCmd.
func (o TxCmd) String() string {
	switch o {
	case CreateTable:
		return "create-table"
	case DeleteTable:
		return "delete-table"
	case Get:
		return "read"
	case Set:
		return "write"
	case Delete:
		return "delete"
	case CmpAndSwap:
		return "compare-and-swap"
	case CmpOrRollback:
		return "compare-and-rollback"
	default:
		return fmt.Sprintf("unknown(%d)", o)
	}
}

// Tx represents a transaction and it's list of multiple TxEntry. Each TxEntry
// represents a read or write operation on the database.
type Tx struct {
	Operations []*TxEntry
}

// CreateTable adds a new create query to the transaction.
func (tx *Tx) CreateTable(bucket []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Cmd:    CreateTable,
	})
}

// DeleteTable adds a new create query to the transaction.
func (tx *Tx) DeleteTable(bucket []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Cmd:    DeleteTable,
	})
}

// Get adds a new read query to the transaction.
func (tx *Tx) Get(bucket, key []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Cmd:    Get,
	})
}

// Set adds a new write query to the transaction.
func (tx *Tx) Set(bucket, key, value []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    Set,
	})
}

// Del adds a new delete query to the transaction.
func (tx *Tx) Del(bucket, key []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Cmd:    Delete,
	})
}

// Cas adds a new compare-and-swap query to the transaction.
func (tx *Tx) Cas(bucket, key, value []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    CmpAndSwap,
	})
}

// Cmp adds a new compare-or-rollback query to the transaction.
func (tx *Tx) Cmp(bucket, key, value []byte) {
	tx.Operations = append(tx.Operations, &TxEntry{
		Bucket: bucket,
		Key:    key,
		Value:  value,
		Cmd:    CmpOrRollback,
	})
}

// TxEntry is the base elements for the transactions, a TxEntry is a read or
// write operation on the database.
type TxEntry struct {
	Bucket   []byte
	Key      []byte
	Value    []byte
	CmpValue []byte
	// Where the result of Get or CmpAndSwap txns is stored.
	Result  []byte
	Cmd     TxCmd
	Swapped bool
}

// Entry is the return value for list commands.
type Entry struct {
	Bucket []byte
	Key    []byte
	Value  []byte
}
