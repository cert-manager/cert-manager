package goacmedns

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

var testAccounts = map[string]Account{
	"lettuceencrypt.org": {
		FullDomain: "lettuceencrypt.org",
		SubDomain:  "tossed.lettuceencrypt.org",
		Username:   "cpu",
		Password:   "hunter2",
	},
	"threeletter.agency": {
		FullDomain: "threeletter.agency",
		SubDomain:  "jobs.threeletter.agency",
		Username:   "spooky.mulder",
		Password:   "trustno1",
	},
}

func TestNewFileStorage(t *testing.T) {
	path := "foo.json"
	mode := os.FileMode(0600)
	storage := NewFileStorage(path, mode)

	fs, ok := storage.(fileStorage)
	if !ok {
		t.Fatalf("expected fileStorage instance from NewFileStorage, got %T", storage)
	}

	if fs.path != path {
		t.Errorf("expected fs.path = %q, got %q", path, fs.path)
	}
	if fs.mode != mode {
		t.Errorf("expected fs.mode = %d, got %d", mode, fs.mode)
	}
	if fs.accounts == nil {
		t.Error("expected accounts to be not-nil, was nil")
	}

	testData, err := json.Marshal(testAccounts)
	if err != nil {
		t.Fatalf("unexpected error marshaling testAccounts: %v", err)
	}

	f, err := ioutil.TempFile("", "acmedns.account")
	defer func() { _ = f.Close() }()

	_, err = f.Write(testData)
	if err != nil {
		t.Errorf("unexpected error writing to tempfile: %v", err)
	}

	storage = NewFileStorage(f.Name(), mode)
	fs, ok = storage.(fileStorage)
	if !ok {
		t.Fatalf("expected fileStorage instance from NewFileStorage, got %T", storage)
	}
	if fs.accounts == nil {
		t.Fatalf("expected accounts to be not-nil, was nil")
	}
	if !reflect.DeepEqual(fs.accounts, testAccounts) {
		t.Errorf("expected to have accounts %#v loaded, had %#v", testAccounts, fs.accounts)
	}
}

func TestFileStorageSave(t *testing.T) {
	f, err := ioutil.TempFile("", "acmedns.account")
	defer func() { _ = f.Close() }()

	if err != nil {
		t.Fatalf("Unable to create tempfile: %v", err)
	}

	storage := NewFileStorage(f.Name(), 0600)

	for d, acct := range testAccounts {
		err := storage.Put(d, acct)
		if err != nil {
			t.Errorf("unexpected error adding account %#v to storage: %v", acct, err)
		}
	}

	err = storage.Save()
	if err != nil {
		t.Fatalf("unexpected error saving storage: %v", err)
	}

	storedJSON, err := ioutil.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("unexpected error reading stored JSON from %q: %v", f.Name(), err)
	}

	var restoredData map[string]Account
	err = json.Unmarshal(storedJSON, &restoredData)
	if err != nil {
		t.Fatalf("unexpected error unmarshaling stored JSON from %q: %v", f.Name(), err)
	}

	if !reflect.DeepEqual(restoredData, testAccounts) {
		t.Errorf("Expected saved accounts and restored accounts to be equal. "+
			"Stored: %#v, Restored: %#v", testAccounts, restoredData)
	}
}

func TestFileStorageFetch(t *testing.T) {
	storage := NewFileStorage("", 0)

	for d, acct := range testAccounts {
		err := storage.Put(d, acct)
		if err != nil {
			t.Errorf("unexpected error adding account %#v to storage: %v", acct, err)
		}
	}

	for d, expected := range testAccounts {
		acct, err := storage.Fetch(d)
		if err != nil {
			t.Errorf("unexpected error fetching domain %q from storage: %v", d, err)
		}
		if !reflect.DeepEqual(acct, expected) {
			t.Errorf("expected domain %q to have account %#v, had %#v\n", d, expected, acct)
		}
	}

	_, err := storage.Fetch("doesnt-exist.example.org")
	if err != ErrDomainNotFound {
		t.Errorf("expected ErrDomainNotFound for Fetch of non-existent domain, got %v", err)
	}
}
