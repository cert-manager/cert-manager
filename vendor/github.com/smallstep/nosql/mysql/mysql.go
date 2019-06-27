package mysql

import (
	"bytes"
	"database/sql"
	"fmt"
	"strings"

	// import mysql driver anonymously (just run the init)
	_ "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"
)

// DB is a wrapper over *sql.DB,
type DB struct {
	db *sql.DB
}

// Open creates a Driver and connects to the database with the given address
// and access details.
func (db *DB) Open(dataSourceName string, opt ...database.Option) error {
	opts := &database.Options{}
	for _, o := range opt {
		if err := o(opts); err != nil {
			return err
		}
	}

	var err error
	_db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return errors.Wrap(err, "error connecting to mysql")
	}
	_, err = _db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", opts.Database))
	if err != nil {
		return errors.Wrapf(err, "error creating database %s (if not exists)", opts.Database)
	}
	db.db, err = sql.Open("mysql", dataSourceName+opts.Database)
	if err != nil {
		return errors.Wrapf(err, "error connecting to mysql database")
	}

	return nil
}

// Close shutsdown the database driver.
func (db *DB) Close() error {
	return errors.WithStack(db.db.Close())
}

func getQry(bucket []byte) string {
	return fmt.Sprintf("SELECT nvalue FROM %s WHERE nkey = ?", bucket)
}

func insertUpdateQry(bucket []byte) string {
	return fmt.Sprintf("INSERT INTO %s(nkey, nvalue) VALUES(?,?) ON DUPLICATE KEY UPDATE nvalue = ?", bucket)
}

func delQry(bucket []byte) string {
	return fmt.Sprintf("DELETE FROM %s WHERE nkey = ?", bucket)
}

func createTableQry(bucket []byte) string {
	return fmt.Sprintf("CREATE TABLE %s(nkey VARBINARY(255), nvalue BLOB, PRIMARY KEY (nkey));", bucket)
}

func deleteTableQry(bucket []byte) string {
	return fmt.Sprintf("DROP TABLE %s", bucket)
}

// Get retrieves the column/row with given key.
func (db *DB) Get(bucket, key []byte) ([]byte, error) {
	var val string
	err := db.db.QueryRow(getQry(bucket), key).Scan(&val)
	switch {
	case err == sql.ErrNoRows:
		return nil, errors.Wrapf(database.ErrNotFound, "%s/%s not found", bucket, key)
	case err != nil:
		return nil, errors.Wrapf(err, "failed to get %s/%s", bucket, key)
	default:
		return []byte(val), nil
	}
}

// Set inserts the key and value into the given bucket(column).
func (db *DB) Set(bucket, key, value []byte) error {
	_, err := db.db.Exec(insertUpdateQry(bucket), key, value, value)
	if err != nil {
		return errors.Wrapf(err, "failed to set %s/%s", bucket, key)
	}
	return nil
}

// Del deletes a row from the database.
func (db *DB) Del(bucket, key []byte) error {
	_, err := db.db.Exec(delQry(bucket), key)
	return errors.Wrapf(err, "failed to delete %s/%s", bucket, key)
}

// List returns the full list of entries in a column.
func (db *DB) List(bucket []byte) ([]*database.Entry, error) {
	rows, err := db.db.Query(fmt.Sprintf("SELECT * FROM %s", bucket))
	if err != nil {
		estr := err.Error()
		if strings.HasPrefix(estr, "Error 1146:") {
			return nil, errors.Wrapf(database.ErrNotFound, estr)
		}
		return nil, errors.Wrapf(err, "error querying table %s", bucket)
	}
	defer rows.Close()
	var (
		key, value string
		entries    []*database.Entry
	)
	for rows.Next() {
		err := rows.Scan(&key, &value)
		if err != nil {
			return nil, errors.Wrap(err, "error getting key and value from row")
		}
		entries = append(entries, &database.Entry{
			Bucket: bucket,
			Key:    []byte(key),
			Value:  []byte(value),
		})
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.Wrap(err, "error accessing row")
	}
	return entries, nil
}

// CmpAndSwap modifies the value at the given bucket and key (to newValue)
// only if the existing (current) value matches oldValue.
func (db *DB) CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	sqlTx, err := db.db.Begin()
	if err != nil {
		return nil, false, errors.WithStack(err)
	}

	val, swapped, err := cmpAndSwap(sqlTx, bucket, key, oldValue, newValue)
	switch {
	case err != nil:
		if err := sqlTx.Rollback(); err != nil {
			return nil, false, errors.Wrapf(err, "failed to execute CmpAndSwap transaction on %s/%s and failed to rollback transaction", bucket, key)
		}
		return nil, false, err
	case swapped:
		if err := sqlTx.Commit(); err != nil {
			return nil, false, errors.Wrapf(err, "failed to commit badger transaction")
		}
		return val, swapped, nil
	default:
		if err := sqlTx.Rollback(); err != nil {
			return nil, false, errors.Wrapf(err, "failed to rollback read-only CmpAndSwap transaction on %s/%s", bucket, key)
		}
		return val, swapped, err
	}
}

func cmpAndSwap(sqlTx *sql.Tx, bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	var current []byte
	err := sqlTx.QueryRow(getQry(bucket), key).Scan(&current)

	if err != nil && err != sql.ErrNoRows {
		return nil, false, err
	}
	if !bytes.Equal(current, oldValue) {
		return current, false, nil
	}

	if _, err = sqlTx.Exec(insertUpdateQry(bucket), key, newValue, newValue); err != nil {
		return nil, false, errors.Wrapf(err, "failed to set %s/%s", bucket, key)
	}
	return newValue, true, nil
}

// Update performs multiple commands on one read-write transaction.
func (db *DB) Update(tx *database.Tx) error {
	sqlTx, err := db.db.Begin()
	if err != nil {
		return errors.WithStack(err)
	}
	rollback := func(err error) error {
		if rollbackErr := sqlTx.Rollback(); rollbackErr != nil {
			return errors.Wrap(err, "UPDATE failed, unable to rollback transaction")
		}
		return errors.Wrap(err, "UPDATE failed")
	}
	for _, q := range tx.Operations {
		// create or delete buckets
		switch q.Cmd {
		case database.CreateTable:
			_, err := sqlTx.Exec(createTableQry(q.Bucket))
			if err != nil {
				return rollback(errors.Wrapf(err, "failed to create table %s", q.Bucket))
			}
		case database.DeleteTable:
			_, err := sqlTx.Exec(deleteTableQry(q.Bucket))
			if err != nil {
				estr := err.Error()
				if strings.HasPrefix(err.Error(), "Error 1051:") {
					return errors.Wrapf(database.ErrNotFound, estr)
				}
				return errors.Wrapf(err, "failed to delete table %s", q.Bucket)
			}
		case database.Get:
			var val string
			err := sqlTx.QueryRow(getQry(q.Bucket), q.Key).Scan(&val)
			switch {
			case err == sql.ErrNoRows:
				return rollback(errors.Wrapf(database.ErrNotFound, "%s/%s not found", q.Bucket, q.Key))
			case err != nil:
				return rollback(errors.Wrapf(err, "failed to get %s/%s", q.Bucket, q.Key))
			default:
				q.Result = []byte(val)
			}
		case database.Set:
			if _, err = sqlTx.Exec(insertUpdateQry(q.Bucket), q.Key, q.Value, q.Value); err != nil {
				return rollback(errors.Wrapf(err, "failed to set %s/%s", q.Bucket, q.Key))
			}
		case database.Delete:
			if _, err = sqlTx.Exec(delQry(q.Bucket), q.Key); err != nil {
				return rollback(errors.Wrapf(err, "failed to delete %s/%s", q.Bucket, q.Key))
			}
		case database.CmpAndSwap:
			q.Result, q.Swapped, err = cmpAndSwap(sqlTx, q.Bucket, q.Key, q.CmpValue, q.Value)
			if err != nil {
				return rollback(errors.Wrapf(err, "failed to load-or-store %s/%s", q.Bucket, q.Key))
			}
		case database.CmpOrRollback:
			return database.ErrOpNotSupported
		default:
			return database.ErrOpNotSupported
		}
	}

	if err = errors.WithStack(sqlTx.Commit()); err != nil {
		return rollback(err)
	}
	return nil
}

// CreateTable creates a table in the database.
func (db *DB) CreateTable(bucket []byte) error {
	_, err := db.db.Exec(createTableQry(bucket))
	if err != nil {
		return errors.Wrapf(err, "failed to create table %s", bucket)
	}
	return nil
}

// DeleteTable deletes a table in the database.
func (db *DB) DeleteTable(bucket []byte) error {
	_, err := db.db.Exec(deleteTableQry(bucket))
	if err != nil {
		estr := err.Error()
		if strings.HasPrefix(err.Error(), "Error 1051:") {
			return errors.Wrapf(database.ErrNotFound, estr)
		}
		return errors.Wrapf(err, "failed to delete table %s", bucket)
	}
	return nil
}
