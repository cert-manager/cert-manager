package bolt

import (
	"bytes"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"
	bolt "go.etcd.io/bbolt"
)

var boltDBSep = []byte("/")

// DB is a wrapper over bolt.DB,
type DB struct {
	db *bolt.DB
}

type boltBucket interface {
	Bucket(name []byte) *bolt.Bucket
	CreateBucket(name []byte) (*bolt.Bucket, error)
	CreateBucketIfNotExists(name []byte) (*bolt.Bucket, error)
	DeleteBucket(name []byte) error
}

// Open opens or creates a DB database in the given path.
func (db *DB) Open(dataSourceName string, opt ...database.Option) (err error) {
	opts := &database.Options{}
	for _, o := range opt {
		if err := o(opts); err != nil {
			return err
		}
	}
	db.db, err = bolt.Open(dataSourceName, 0600, &bolt.Options{Timeout: 5 * time.Second})
	return errors.WithStack(err)
}

// Close closes the DB database.
func (db *DB) Close() error {
	return errors.WithStack(db.db.Close())
}

// CreateTable creates a bucket or an embedded bucket if it does not exists.
func (db *DB) CreateTable(bucket []byte) error {
	return db.db.Update(func(tx *bolt.Tx) error {
		return db.createBucket(tx, bucket)
	})
}

// DeleteTable deletes a root or embedded bucket. Returns an error if the
// bucket cannot be found or if the key represents a non-bucket value.
func (db *DB) DeleteTable(bucket []byte) error {
	return db.db.Update(func(tx *bolt.Tx) error {
		return db.deleteBucket(tx, bucket)
	})
}

// Get returns the value stored in the given bucked and key.
func (db *DB) Get(bucket, key []byte) (ret []byte, err error) {
	err = db.db.View(func(tx *bolt.Tx) error {
		b, err := db.getBucket(tx, bucket)
		if err != nil {
			return err
		}
		ret = b.Get(key)
		if ret == nil {
			return database.ErrNotFound
		}
		// Make sure to return a copy as ret is only valid during the
		// transaction.
		ret = cloneBytes(ret)
		return nil
	})
	return
}

// Set stores the given value on bucket and key.
func (db *DB) Set(bucket, key, value []byte) error {
	return db.db.Update(func(tx *bolt.Tx) error {
		b, err := db.getBucket(tx, bucket)
		if err != nil {
			return err
		}
		return errors.WithStack(b.Put(key, value))
	})
}

// Del deletes the value stored in the given bucked and key.
func (db *DB) Del(bucket, key []byte) error {
	return db.db.Update(func(tx *bolt.Tx) error {
		b, err := db.getBucket(tx, bucket)
		if err != nil {
			return err
		}
		return errors.WithStack(b.Delete(key))
	})
}

// List returns the full list of entries in a bucket.
func (db *DB) List(bucket []byte) ([]*database.Entry, error) {
	var entries []*database.Entry
	err := db.db.View(func(tx *bolt.Tx) error {
		b, err := db.getBucket(tx, bucket)
		if err != nil {
			return errors.Wrap(err, "getBucket failed")
		}

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			entries = append(entries, &database.Entry{
				Bucket: bucket,
				Key:    cloneBytes(k),
				Value:  cloneBytes(v),
			})
		}
		return nil
	})
	return entries, err
}

// CmpAndSwap modifies the value at the given bucket and key (to newValue)
// only if the existing (current) value matches oldValue.
func (db *DB) CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	boltTx, err := db.db.Begin(true)
	if err != nil {
		return nil, false, errors.Wrap(err, "error creating Bolt transaction")
	}

	boltBucket := boltTx.Bucket(bucket)
	if boltBucket == nil {
		return nil, false, errors.Errorf("failed to get bucket %s", bucket)
	}

	val, swapped, err := cmpAndSwap(boltBucket, key, oldValue, newValue)
	switch {
	case err != nil:
		if err := boltTx.Rollback(); err != nil {
			return nil, false, errors.Wrapf(err, "failed to execute CmpAndSwap transaction on %s/%s and failed to rollback transaction", bucket, key)
		}
		return nil, false, err
	case swapped:
		if err := boltTx.Commit(); err != nil {
			return nil, false, errors.Wrapf(err, "failed to commit badger transaction")
		}
		return val, swapped, nil
	default:
		if err := boltTx.Rollback(); err != nil {
			return nil, false, errors.Wrapf(err, "failed to rollback read-only CmpAndSwap transaction on %s/%s", bucket, key)
		}
		return val, swapped, err
	}
}

func cmpAndSwap(boltBucket *bolt.Bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	current := boltBucket.Get(key)
	if !bytes.Equal(current, oldValue) {
		return cloneBytes(current), false, nil
	}

	if err := boltBucket.Put(key, newValue); err != nil {
		return nil, false, errors.Wrapf(err, "failed to set key %s", key)
	}
	return newValue, true, nil
}

// Update performs multiple commands on one read-write transaction.
func (db *DB) Update(tx *database.Tx) error {
	return db.db.Update(func(boltTx *bolt.Tx) (err error) {
		var b *bolt.Bucket
		for _, q := range tx.Operations {
			// create or delete buckets
			switch q.Cmd {
			case database.CreateTable:
				err = db.createBucket(boltTx, q.Bucket)
				if err != nil {
					return err
				}
				continue
			case database.DeleteTable:
				err = db.deleteBucket(boltTx, q.Bucket)
				if err != nil {
					return err
				}
				continue
			}

			// For other operations, get bucket and perform operation
			b = boltTx.Bucket(q.Bucket)

			switch q.Cmd {
			case database.Get:
				ret := b.Get(q.Key)
				if ret == nil {
					return errors.WithStack(database.ErrNotFound)
				}
				q.Result = cloneBytes(ret)
			case database.Set:
				if err = b.Put(q.Key, q.Value); err != nil {
					return errors.WithStack(err)
				}
			case database.Delete:
				if err = b.Delete(q.Key); err != nil {
					return errors.WithStack(err)
				}
			case database.CmpAndSwap:
				q.Result, q.Swapped, err = cmpAndSwap(b, q.Key, q.CmpValue, q.Value)
				if err != nil {
					return errors.Wrapf(err, "failed to execute CmpAndSwap on %s/%s", q.Bucket, q.Key)
				}
			case database.CmpOrRollback:
				return errors.Errorf("operation '%s' is not yet implemented", q.Cmd)
			default:
				return errors.Errorf("operation '%s' is not supported", q.Cmd)
			}
		}
		return nil
	})
}

// getBucket returns the bucket supporting nested buckets, nested buckets are
// bucket names separated by '/'.
func (db *DB) getBucket(tx *bolt.Tx, name []byte) (b *bolt.Bucket, err error) {
	buckets := bytes.Split(name, boltDBSep)
	for i, n := range buckets {
		if i == 0 {
			b = tx.Bucket(n)
		} else {
			b = b.Bucket(n)
		}
		if b == nil {
			return nil, database.ErrNotFound
		}
	}
	return
}

// createBucket creates a bucket or a nested bucket in the given transaction.
func (db *DB) createBucket(tx *bolt.Tx, name []byte) (err error) {
	b := boltBucket(tx)
	buckets := bytes.Split(name, boltDBSep)
	for _, name := range buckets {
		b, err = b.CreateBucketIfNotExists(name)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return
}

// deleteBucket deletes a bucket or a nested bucked in the given transaction.
func (db *DB) deleteBucket(tx *bolt.Tx, name []byte) (err error) {
	b := boltBucket(tx)
	buckets := bytes.Split(name, boltDBSep)
	last := len(buckets) - 1
	for i := 0; i < last; i++ {
		if b = b.Bucket(buckets[i]); b == nil {
			return errors.Wrapf(database.ErrNotFound, "bucket %s does not exist", bytes.Join(buckets[0:i+1], boltDBSep))
		}
	}
	err = b.DeleteBucket(buckets[last])
	if err == bolt.ErrBucketNotFound {
		return errors.Wrapf(database.ErrNotFound, "bucket %s does not exist", name)
	}
	return
}

// cloneBytes returns a copy of a given slice.
func cloneBytes(v []byte) []byte {
	var clone = make([]byte, len(v))
	copy(clone, v)
	return clone
}
