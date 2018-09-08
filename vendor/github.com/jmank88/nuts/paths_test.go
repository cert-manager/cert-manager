//go:generate rm -rf testdata
//
//go:generate go run cmd/testpaths/main.go testdata standard 10 100 1000 10000 100000 1000000
//go:generate go run cmd/testpaths/main.go testdata segmentCount 1 5 10 50 100
//go:generate go run cmd/testpaths/main.go testdata branchFactor 1 5 10 50 100 500 1000 5000 10000
//go:generate go run cmd/testpaths/main.go testdata segmentSize 1 5 10 50 100 200
//
//go:generate go run cmd/testdb/main.go testdata
package nuts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boltdb/bolt"
)

var bucketName = []byte("testBucket")

func exDB(f func(db *bolt.DB)) {
	tmp := tempfile()
	defer os.Remove(tmp)
	db, err := bolt.Open(tmp, 0666, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	f(db)
}

func ExampleSeekPathMatch() {
	exDB(func(db *bolt.DB) {
		if err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucket(bucketName)
			if err != nil {
				return err
			}

			// Put a variable path.
			return b.Put([]byte("/blogs/:blog_id/comments/:comment_id"), []byte{})
		}); err != nil {
			log.Fatal(err)
		}

		if err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketName)

			// Match path.
			path, _ := SeekPathMatch(b.Cursor(), []byte("/blogs/asdf/comments/42"))
			fmt.Println(string(path))

			return nil
		}); err != nil {
			log.Fatal(err)
		}
	})

	// Output: /blogs/:blog_id/comments/:comment_id
}

func ExampleSeekPathConflict() {
	exDB(func(db *bolt.DB) {
		insert := func(path string) {
			if err := db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucketIfNotExists(bucketName)
				if err != nil {
					return err
				}

				// Check for conflicts.
				if k, _ := SeekPathConflict(b.Cursor(), []byte(path)); k != nil {
					fmt.Printf("Put(%s) blocked - conflict: %s\n", path, string(k))
					return nil
				}

				// Put.
				if err := b.Put([]byte(path), []byte{}); err != nil {
					return err
				}
				fmt.Printf("Put(%s)\n", path)
				return nil
			}); err != nil {
				log.Fatal(err)
			}
		}
		// Put
		insert("/blogs/")
		// Put
		insert("/blogs/:blog_id")
		// Conflict
		insert("/blogs/a_blog")
	})

	// Output:
	// Put(/blogs/)
	// Put(/blogs/:blog_id)
	// Put(/blogs/a_blog) blocked - conflict: /blogs/:blog_id
}

var matchTests = []struct {
	path    string
	matches []string
}{
	{`/blogs`, []string{`/blogs`}},
	{`/blogs/`, []string{`/blogs/`}},
	{`/blogs/:blog_id`, []string{`/blogs/123`}},
	{`/blogs/:blog_id/comments`, []string{`/blogs/123/comments`}},
	{`/blogs/:blog_id/comments/`, []string{`/blogs/123/comments/`}},
	{`/blogs/:blog_id/comments/:comment_id`, []string{`/blogs/123/comments/456`}},
	{`/blogs/:blog_id/comments/:comment_id/*suffix`,
		[]string{`/blogs/123/comments/456/test`, `/blogs/123/comments/456/test/test`}},
}

func TestMatchPath(t *testing.T) {
	testDB(t, func(db *bolt.DB) {
		bucketName := []byte("testBucket")

		// Setup - Put all paths
		if err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucket(bucketName)
			if err != nil {
				return err
			}
			for _, test := range matchTests {
				err := b.Put([]byte(test.path), []byte{})
				if err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal("failed to insert paths:", err)
		}

		// Test - Match each
		if err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketName)
			for _, test := range matchTests {
				for _, match := range test.matches {
					k, _ := SeekPathMatch(b.Cursor(), []byte(match))
					if k == nil {
						t.Errorf("expected %q to match %q but got none", match, test.path)
					} else if !bytes.Equal(k, []byte(test.path)) {
						t.Errorf("expected %q to match %q but got %q", match, test.path, string(k))
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal("tests failed:", err)
		}
	})
}

func TestConflicts(t *testing.T) {
	for _, test := range []struct {
		path      string
		conflicts []string
	}{
		{`/test/test`, []string{`/test/test`, `/:test`, `/*test`, `/test/:test`, `/test/*test`, `/:test/test`}},
		{`/:test`, []string{`/:tst`, `/test`, `/*test`}},
		{`/test/*test`, []string{`/test/*tst`, `/test/test`, `/test/:tst`, `/test/test/test`, `/test/test/:test`, `/test/test/*test`}},
	} {
		testDB(t, func(db *bolt.DB) {
			// Setup - Put path
			if err := db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucket(bucketName)
				if err != nil {
					return err
				}
				return b.Put([]byte(test.path), []byte{})
			}); err != nil {
				t.Fatal("failed to insert path", err)
			}

			// Test - Verify all conflicts
			if err := db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucketName)
				for _, c := range test.conflicts {
					k, _ := SeekPathConflict(b.Cursor(), []byte(c))
					kStr := string(k)
					if kStr != test.path {
						t.Errorf("expected %q to match %q but got %q", c, test.path, kStr)
					}
				}
				return nil
			}); err != nil {
				t.Fatal("failed to run tests", err)
			}
		})
	}
}

// Attempts to put all matchTests w/o conflict.
func TestNoConflicts(t *testing.T) {
	testDB(t, func(db *bolt.DB) {
		bucketName := []byte("testBucket")

		if err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucket(bucketName)
			if err != nil {
				return err
			}
			c := b.Cursor()
			for _, test := range matchTests {
				pathB := []byte(test.path)
				if k, _ := SeekPathConflict(c, pathB); k != nil {
					t.Errorf("unexpected conflict with %q: %s", test.path, string(k))
				}

				if err := b.Put(pathB, []byte{}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal("failed to insert paths:", err)
		}
	})
}

func Benchmark(b *testing.B) {
	b.Run("standard", forEachDB("standard", strings.NewReplacer(":", "", "*", "").Replace))
	b.Run("branchFactor", forEachDB("branchFactor", nil))
	b.Run("segmentCount", forEachDB("segmentCount", nil))
	b.Run("segmentSize", forEachDB("segmentSize", nil))
}

func forEachDB(testname string, fn func(path string) string) func(*testing.B) {
	return func(b *testing.B) {
		dir := filepath.Join("testdata", testname)
		err := filepath.Walk(dir, func(testfile string, info os.FileInfo, err error) error {
			if !info.IsDir() && filepath.Ext(testfile) == ".db" {
				arg := strings.TrimSuffix(filepath.Base(testfile), ".db")

				b.Run(arg, benchMatch(testfile, fn))
			}
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchMatch(testdb string, pathFn func(path string) string) func(b *testing.B) {
	return func(b *testing.B) {
		db, err := bolt.Open(testdb, 0666, nil)
		if err != nil {
			b.Fatalf("failed to open database %s: %s", testdb, err)
		}
		defer db.Close()

		testtxt := strings.TrimSuffix(testdb, ".db") + ".txt"
		f, err := os.Open(testtxt)
		if err != nil {
			b.Fatalf("failed to open file %s: %s", testtxt, err)
		}

		var paths [][]byte
		func() {
			defer f.Close()

			// Use default, ScanLines
			s := bufio.NewScanner(f)

			paths = make([][]byte, 0, b.N)
			for s.Scan() {
				if pathFn == nil {
					paths = append(paths, s.Bytes())
				} else {
					paths = append(paths, []byte(pathFn(s.Text())))
				}

				if len(paths) == cap(paths) {
					break
				}
			}
			if s.Err() != nil {
				b.Fatal("failed to read text paths:", s.Err())
			}
		}()

		b.ResetTimer()

		lookup := func(path []byte) error {
			return db.View(func(tx *bolt.Tx) error {
				bk := tx.Bucket([]byte("paths"))
				k, _ := SeekPathMatch(bk.Cursor(), path)
				if k == nil {
					return errors.New("no match found")
				}
				return nil
			})
		}

		for i := 0; i < b.N; i++ {
			path := paths[i%len(paths)]

			if err := lookup(path); err != nil {
				b.Fatalf("failed to match %q: %s", string(path), err)
			}
		}
	}
}

func testDB(t *testing.T, f func(db *bolt.DB)) {
	tmp := tempfile()
	defer os.Remove(tmp)
	db, err := bolt.Open(tmp, 0666, nil)
	if err != nil {
		t.Fatal("failed to open db:", err)
	}
	defer db.Close()
	f(db)
}

func tempfile() string {
	f, err := ioutil.TempFile("", "nuts-bolt-")
	if err != nil {
		panic(err)
	}
	if err := f.Close(); err != nil {
		panic(err)
	}
	if err := os.Remove(f.Name()); err != nil {
		panic(err)
	}
	return f.Name()
}
