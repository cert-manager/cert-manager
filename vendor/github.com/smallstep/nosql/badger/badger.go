package badger

import (
	"bytes"
	"encoding/binary"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"
)

// DB is a wrapper over *badger.DB,
type DB struct {
	db *badger.DB
}

// Open opens or creates a BoltDB database in the given path.
func (db *DB) Open(dir string, opt ...database.Option) (err error) {
	opts := &database.Options{}
	for _, o := range opt {
		if err := o(opts); err != nil {
			return err
		}
	}

	bo := badger.DefaultOptions
	bo.Dir = dir
	if opts.ValueDir != "" {
		bo.ValueDir = opts.ValueDir
	} else {
		bo.ValueDir = dir
	}

	db.db, err = badger.Open(bo)
	return errors.Wrap(err, "error opening Badger database")
}

// Close closes the DB database.
func (db *DB) Close() error {
	return errors.Wrap(db.db.Close(), "error closing Badger database")
}

// CreateTable creates a token element with the 'bucket' prefix so that such
// that their appears to be a table.
func (db *DB) CreateTable(bucket []byte) error {
	bk, err := badgerEncode(bucket)
	if err != nil {
		return err
	}
	return db.db.Update(func(txn *badger.Txn) error {
		return errors.Wrapf(txn.Set(bk, []byte{}), "failed to create %s/", bucket)
	})
}

// DeleteTable deletes a root or embedded bucket. Returns an error if the
// bucket cannot be found or if the key represents a non-bucket value.
func (db *DB) DeleteTable(bucket []byte) error {
	var tableExists bool
	prefix, err := badgerEncode(bucket)
	if err != nil {
		return err
	}
	deleteKeys := func(keysForDelete [][]byte) error {
		if err := db.db.Update(func(txn *badger.Txn) error {
			for _, key := range keysForDelete {
				tableExists = true
				if err := txn.Delete(key); err != nil {
					return errors.Wrapf(err, "error deleting key %s", key)
				}
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "update failed")
		}
		return nil
	}

	collectSize := 1000
	err = db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.AllVersions = false
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		keysForDelete := make([][]byte, collectSize)
		keysCollected := 0
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := it.Item().KeyCopy(nil)
			keysForDelete[keysCollected] = key
			keysCollected++
			if keysCollected == collectSize {
				if err := deleteKeys(keysForDelete); err != nil {
					return err
				}
				keysCollected = 0
			}
		}
		if keysCollected > 0 {
			if err := deleteKeys(keysForDelete[:keysCollected]); err != nil {
				return err
			}
		}
		if !tableExists {
			return errors.Wrapf(database.ErrNotFound, "table %s does not exist", bucket)
		}

		return nil
	})
	return err
}

// badgerGet is a helper for the Get method.
func badgerGet(txn *badger.Txn, key []byte) ([]byte, error) {
	item, err := txn.Get(key)
	switch {
	case err == badger.ErrKeyNotFound:
		return nil, errors.Wrapf(database.ErrNotFound, "key %s not found", key)
	case err != nil:
		return nil, errors.Wrapf(err, "failed to get key %s", key)
	default:
		val, err := item.Value()
		if err != nil {
			return nil, errors.Wrap(err, "error accessing value returned by database")
		}

		// Make sure to return a copy as val is only valid during the
		// transaction.
		return cloneBytes(val), nil
	}
}

// Get returns the value stored in the given bucked and key.
func (db *DB) Get(bucket, key []byte) (ret []byte, err error) {
	bk, err := toBadgerKey(bucket, key)
	if err != nil {
		return nil, errors.Wrapf(err, "error converting %s/%s to badgerKey", bucket, key)
	}
	err = db.db.View(func(txn *badger.Txn) error {
		ret, err = badgerGet(txn, bk)
		return err
	})
	return
}

// Set stores the given value on bucket and key.
func (db *DB) Set(bucket, key, value []byte) error {
	bk, err := toBadgerKey(bucket, key)
	if err != nil {
		return errors.Wrapf(err, "error converting %s/%s to badgerKey", bucket, key)
	}
	return db.db.Update(func(txn *badger.Txn) error {
		return errors.Wrapf(txn.Set(bk, value), "failed to set %s/%s", bucket, key)
	})
}

// Del deletes the value stored in the given bucked and key.
func (db *DB) Del(bucket, key []byte) error {
	bk, err := toBadgerKey(bucket, key)
	if err != nil {
		return errors.Wrapf(err, "error converting %s/%s to badgerKey", bucket, key)
	}
	return db.db.Update(func(txn *badger.Txn) error {
		return errors.Wrapf(txn.Delete(bk), "failed to delete %s/%s", bucket, key)
	})
}

// List returns the full list of entries in a bucket.
func (db *DB) List(bucket []byte) ([]*database.Entry, error) {
	var (
		entries     []*database.Entry
		tableExists bool
	)
	err := db.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix, err := badgerEncode(bucket)
		if err != nil {
			return err
		}
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			tableExists = true
			item := it.Item()
			bk := item.KeyCopy(nil)
			if isBadgerTable(bk) {
				continue
			}
			_bucket, key, err := fromBadgerKey(bk)
			if err != nil {
				return errors.Wrapf(err, "error converting from badgerKey %s", bk)
			}
			if !bytes.Equal(_bucket, bucket) {
				return errors.Errorf("bucket names do not match; want %v, but got %v",
					bucket, _bucket)
			}
			v, err := item.Value()
			if err != nil {
				return errors.Wrap(err, "error retrieving contents from database value")
			}
			entries = append(entries, &database.Entry{
				Bucket: _bucket,
				Key:    key,
				Value:  cloneBytes(v),
			})
		}
		if !tableExists {
			return errors.Wrapf(database.ErrNotFound, "bucket %s not found", bucket)
		}
		return nil
	})
	return entries, err
}

// CmpAndSwap modifies the value at the given bucket and key (to newValue)
// only if the existing (current) value matches oldValue.
func (db *DB) CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	bk, err := toBadgerKey(bucket, key)
	if err != nil {
		return nil, false, err
	}

	badgerTxn := db.db.NewTransaction(true)
	defer badgerTxn.Discard()

	val, swapped, err := cmpAndSwap(badgerTxn, bk, oldValue, newValue)
	switch {
	case err != nil:
		return nil, false, err
	case swapped:
		if err := badgerTxn.Commit(nil); err != nil {
			return nil, false, errors.Wrapf(err, "failed to commit badger transaction")
		}
		return val, swapped, nil
	default:
		return val, swapped, err
	}
}

func cmpAndSwap(badgerTxn *badger.Txn, bk, oldValue, newValue []byte) ([]byte, bool, error) {
	current, err := badgerGet(badgerTxn, bk)
	// If value does not exist but expected is not nil, then return w/out swapping.
	if err != nil && !database.IsErrNotFound(err) {
		return nil, false, err
	}
	if !bytes.Equal(current, oldValue) {
		return current, false, nil
	}

	if err := badgerTxn.Set(bk, newValue); err != nil {
		return current, false, errors.Wrapf(err, "failed to set %s", bk)
	}
	return newValue, true, nil
}

// Update performs multiple commands on one read-write transaction.
func (db *DB) Update(txn *database.Tx) error {
	return db.db.Update(func(badgerTxn *badger.Txn) (err error) {
		for _, q := range txn.Operations {
			switch q.Cmd {
			case database.CreateTable:
				if err = db.CreateTable(q.Bucket); err != nil {
					return err
				}
				continue
			case database.DeleteTable:
				if err = db.DeleteTable(q.Bucket); err != nil {
					return err
				}
				continue
			}
			bk, err := toBadgerKey(q.Bucket, q.Key)
			if err != nil {
				return err
			}
			switch q.Cmd {
			case database.Get:
				if q.Result, err = badgerGet(badgerTxn, bk); err != nil {
					return errors.Wrapf(err, "failed to get %s/%s", q.Bucket, q.Key)
				}
			case database.Set:
				if err := badgerTxn.Set(bk, q.Value); err != nil {
					return errors.Wrapf(err, "failed to set %s/%s", q.Bucket, q.Key)
				}
			case database.Delete:
				if err = badgerTxn.Delete(bk); err != nil {
					return errors.Wrapf(err, "failed to delete %s/%s", q.Bucket, q.Key)
				}
			case database.CmpAndSwap:
				q.Result, q.Swapped, err = cmpAndSwap(badgerTxn, bk, q.CmpValue, q.Value)
				if err != nil {
					return errors.Wrapf(err, "failed to CmpAndSwap %s/%s", q.Bucket, q.Key)
				}
			case database.CmpOrRollback:
				return database.ErrOpNotSupported
			default:
				return database.ErrOpNotSupported
			}
		}
		return nil
	})
}

// toBadgerKey returns the Badger database key using the following algorithm:
// First 2 bytes are the length of the bucket/table name in little endian format,
// followed by the bucket/table name,
// followed by 2 bytes representing the length of the key in little endian format,
// followed by the key.
func toBadgerKey(bucket, key []byte) ([]byte, error) {
	first, err := badgerEncode(bucket)
	if err != nil {
		return nil, err
	}
	second, err := badgerEncode(key)
	if err != nil {
		return nil, err
	}
	return append(first, second...), nil
}

// isBadgerTable returns True if the slice is a badgerTable token, false otherwise.
// badgerTable means that the slice contains only the [size|value] of one section
// of a badgerKey and no remainder. A badgerKey is [buket|key], while a badgerTable
// is only the bucket section.
func isBadgerTable(bk []byte) bool {
	if k, rest := parseBadgerEncode(bk); len(k) > 0 && len(rest) == 0 {
		return true
	}
	return false
}

// fromBadgerKey returns the bucket and key encoded in a BadgerKey.
// See documentation for toBadgerKey.
func fromBadgerKey(bk []byte) ([]byte, []byte, error) {
	bucket, rest := parseBadgerEncode(bk)
	if len(bucket) == 0 || len(rest) == 0 {
		return nil, nil, errors.Errorf("invalid badger key: %v", bk)
	}

	key, rest2 := parseBadgerEncode(rest)
	if len(key) == 0 || len(rest2) != 0 {
		return nil, nil, errors.Errorf("invalid badger key: %v", bk)
	}

	return bucket, key, nil
}

// badgerEncode encodes a byte slice into a section of a BadgerKey.
// See documentation for toBadgerKey.
func badgerEncode(val []byte) ([]byte, error) {
	l := len(val)
	switch {
	case l == 0:
		return nil, errors.Errorf("input cannot be empty")
	case l > 65535:
		return nil, errors.Errorf("length of input cannot be greater than 65535")
	default:
		lb := new(bytes.Buffer)
		if err := binary.Write(lb, binary.LittleEndian, uint16(l)); err != nil {
			return nil, errors.Wrap(err, "error doing binary Write")
		}
		return append(lb.Bytes(), val...), nil
	}
}

func parseBadgerEncode(bk []byte) (value, rest []byte) {
	var (
		keyLen uint16
		start  = uint16(2)
		length = uint16(len(bk))
	)
	if uint16(len(bk)) < start {
		return nil, bk
	}
	// First 2 bytes stores the length of the value.
	if err := binary.Read(bytes.NewReader(bk[:2]), binary.LittleEndian, &keyLen); err != nil {
		return nil, bk
	}
	end := start + keyLen
	switch {
	case length < end:
		return nil, bk
	case length == end:
		return bk[start:end], nil
	default:
		return bk[start:end], bk[end:]
	}
}

// cloneBytes returns a copy of a given slice.
func cloneBytes(v []byte) []byte {
	var clone = make([]byte, len(v))
	copy(clone, v)
	return clone
}
