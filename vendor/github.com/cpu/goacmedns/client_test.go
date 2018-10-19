package goacmedns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

var (
	errBody  = []byte(`{"error":"this is a test"}`)
	testAcct = Account{
		FullDomain: "lettuceencrypt.org",
		SubDomain:  "tossed.lettuceencrypt.org",
		Username:   "cpu",
		Password:   "hunter2",
	}
)

func errHandler(resp http.ResponseWriter, req *http.Request) {
	resp.WriteHeader(http.StatusBadRequest)
	_, _ = resp.Write(errBody)
}

func newRegHandler(t *testing.T, expectedAllowFrom []string) func(http.ResponseWriter, *http.Request) {
	return func(resp http.ResponseWriter, req *http.Request) {
		expectedCT := "application/json"
		if ct := req.Header.Get("Content-Type"); ct != expectedCT {
			t.Errorf("expected Content-Type %q got %q", expectedCT, ct)
		}
		if ua := req.Header.Get("User-Agent"); ua != userAgent() {
			t.Errorf("expected User-Agent %q got %q", userAgent(), ua)
		}
		if len(expectedAllowFrom) > 0 {
			decoder := json.NewDecoder(req.Body)
			var regReq struct {
				AllowFrom []string
			}
			err := decoder.Decode(&regReq)
			if err != nil {
				t.Fatalf("error decoding request body JSON: %v", err)
			}
			if !reflect.DeepEqual(regReq.AllowFrom, expectedAllowFrom) {
				t.Errorf("expected AllowFrom %#v, got %#v", expectedAllowFrom, regReq.AllowFrom)
			}
		}
		resp.WriteHeader(http.StatusCreated)
		newRegBody, _ := json.Marshal(testAcct)
		_, _ = resp.Write(newRegBody)
	}
}

func TestRegisterAccount(t *testing.T) {
	testAllowFrom := []string{"space", "earth"}

	testCases := []struct {
		Name            string
		RegisterHandler func(http.ResponseWriter, *http.Request)
		AllowFrom       []string
		ExpectedErr     *ClientError
		ExpectedAccount *Account
	}{
		{
			Name:            "registration failure",
			RegisterHandler: errHandler,
			ExpectedErr: &ClientError{
				HTTPStatus: http.StatusBadRequest,
				Body:       errBody,
				Message:    "failed to register account",
			},
		},
		{
			Name:            "registration success",
			RegisterHandler: newRegHandler(t, nil),
			ExpectedAccount: &testAcct,
		},
		{
			Name:            "registration success, allow from",
			AllowFrom:       testAllowFrom,
			RegisterHandler: newRegHandler(t, testAllowFrom),
			ExpectedAccount: &testAcct,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/register", tc.RegisterHandler)

			ts := httptest.NewServer(mux)
			defer ts.Close()

			client := NewClient(ts.URL)
			acct, err := client.RegisterAccount(tc.AllowFrom)

			if tc.ExpectedErr == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tc.ExpectedErr != nil && err == nil {
				t.Errorf("expected error %v, got nil", tc.ExpectedErr)
			} else if tc.ExpectedErr != nil && err != nil {
				if cErr, ok := err.(ClientError); !ok {
					t.Fatalf("expected ClientError from RegisterAccount. Got %v", err)
				} else if !reflect.DeepEqual(cErr, *tc.ExpectedErr) {
					t.Errorf("expected err %#v, got %#v\n", tc.ExpectedErr, cErr)
				}
			} else if tc.ExpectedErr == nil && err == nil {
				if !reflect.DeepEqual(acct, *tc.ExpectedAccount) {
					t.Errorf("expected account %v, got %v\n", tc.ExpectedAccount, acct)
				}
			}
		})
	}
}

const (
	updateValue = "idkmybffjill"
)

func updateTXTHandler(t *testing.T) func(http.ResponseWriter, *http.Request) {
	return func(resp http.ResponseWriter, req *http.Request) {
		expectedCT := "application/json"
		if ct := req.Header.Get("Content-Type"); ct != expectedCT {
			t.Errorf("expected Content-Type %q got %q", expectedCT, ct)
		}
		if ua := req.Header.Get("User-Agent"); ua != userAgent() {
			t.Errorf("expected User-Agent %q got %q", userAgent(), ua)
		}
		if key := req.Header.Get("X-Api-Key"); key != testAcct.Password {
			t.Errorf("expected X-Api-Key %q got %q", testAcct.Password, key)
		}
		if user := req.Header.Get("X-Api-User"); user != testAcct.Username {
			t.Errorf("expected X-Api-User %q got %q", testAcct.Username, user)
		}
		decoder := json.NewDecoder(req.Body)
		var updateReq struct {
			SubDomain string
			Txt       string
		}
		err := decoder.Decode(&updateReq)
		if err != nil {
			t.Fatalf("error decoding request body JSON: %v", err)
		}
		if updateReq.SubDomain != testAcct.SubDomain {
			t.Errorf("expected update req to have SubDomain %q, had %q",
				testAcct.SubDomain, updateReq.SubDomain)
		}
		if updateReq.Txt != updateValue {
			t.Errorf("expected update req to have Txt %q, had %q",
				updateValue, updateReq.Txt)
		}
		resp.WriteHeader(http.StatusOK)
		_, _ = resp.Write([]byte(`{}`))
	}
}

func TestUpdateTXTRecord(t *testing.T) {
	testCases := []struct {
		Name          string
		UpdateHandler func(http.ResponseWriter, *http.Request)
		Value         string
		ExpectedErr   *ClientError
	}{
		{
			Name:          "update failure",
			UpdateHandler: errHandler,
			ExpectedErr: &ClientError{
				HTTPStatus: http.StatusBadRequest,
				Body:       errBody,
				Message:    "failed to update txt record",
			},
		},
		{
			Name:          "update success",
			UpdateHandler: updateTXTHandler(t),
			ExpectedErr:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/update", tc.UpdateHandler)

			ts := httptest.NewServer(mux)
			defer ts.Close()

			client := NewClient(ts.URL)
			err := client.UpdateTXTRecord(testAcct, updateValue)

			if tc.ExpectedErr == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tc.ExpectedErr != nil && err == nil {
				t.Errorf("expected error %v, got nil", tc.ExpectedErr)
			} else if tc.ExpectedErr != nil && err != nil {
				if cErr, ok := err.(ClientError); !ok {
					t.Fatalf("expected ClientError from UpdateTXTRecord. Got %v", err)
				} else if !reflect.DeepEqual(cErr, *tc.ExpectedErr) {
					t.Errorf("expected err %#v, got %#v\n", tc.ExpectedErr, cErr)
				}
			}
		})
	}
}
