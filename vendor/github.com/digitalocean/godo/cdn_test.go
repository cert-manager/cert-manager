package godo

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestCDN_ListCDN(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(
			w,
			`{
        "endpoints": [
          {
            "id": "892071a0-bb95-49bc-8021-3afd67a210bf",
            "origin": "my-space.nyc3.digitaloceanspaces.com",
            "endpoint": "my-space.nyc3.cdn.digitaloceanspaces.com",
            "ttl": 3600,
            "created_at": "2012-10-02T15:00:01.05Z"
          },
          {
            "id": "892071a0-bb95-55bd-8021-3afd67a210bf",
            "origin": "my-space1.nyc3.digitaloceanspaces.com",
            "endpoint": "my-space1.nyc3.cdn.digitaloceanspaces.com",
            "ttl": 3600,
            "created_at": "2012-10-03T15:00:01.05Z"
          }
        ]
      }`,
		)
	})

	cdns, _, err := client.CDNs.List(ctx, nil)
	if err != nil {
		t.Errorf("CDNs.List returned error: %v", err)
	}

	expected := []CDN{
		{
			ID:        "892071a0-bb95-49bc-8021-3afd67a210bf",
			Origin:    "my-space.nyc3.digitaloceanspaces.com",
			Endpoint:  "my-space.nyc3.cdn.digitaloceanspaces.com",
			TTL:       3600,
			CreatedAt: time.Date(2012, 10, 02, 15, 00, 01, 50000000, time.UTC),
		},
		{
			ID:        "892071a0-bb95-55bd-8021-3afd67a210bf",
			Origin:    "my-space1.nyc3.digitaloceanspaces.com",
			Endpoint:  "my-space1.nyc3.cdn.digitaloceanspaces.com",
			TTL:       3600,
			CreatedAt: time.Date(2012, 10, 03, 15, 00, 01, 50000000, time.UTC),
		},
	}

	if !reflect.DeepEqual(cdns, expected) {
		t.Errorf("CDNs.List returned %+v, expected %+v", cdns, expected)
	}
}

func TestCDN_ListCDNMultiplePages(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(
			w,
			`{
        "endpoints": [
          {
            "id": "892071a0-bb95-49bc-8021-3afd67a210bf",
            "origin": "my-space.nyc3.digitaloceanspaces.com",
            "endpoint": "my-space.nyc3.cdn.digitaloceanspaces.com",
            "ttl": 3600,
            "created_at": "2012-10-02T15:00:01.05Z"
          },
          {
            "id": "892071a0-bb95-55bd-8021-3afd67a210bf",
            "origin": "my-space1.nyc3.digitaloceanspaces.com",
            "endpoint": "my-space1.nyc3.cdn.digitaloceanspaces.com",
            "ttl": 3600,
            "created_at": "2012-10-03T15:00:01.05Z"
          }
        ],
        "links":{"pages":{"next":"http://example.com/v2/cdn/endpoints/?page=2"}}
      }`,
		)
	})

	_, resp, err := client.CDNs.List(ctx, nil)
	if err != nil {
		t.Errorf("CDNs.List multiple page returned error: %v", err)
	}

	checkCurrentPage(t, resp, 1)
}

func TestCDN_RetrievePageByNumber(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(
			w,
			`{
        "endpoints": [
          {
            "id": "892071a0-bb95-49bc-8021-3afd67a210bf",
            "origin": "my-space.nyc3.digitaloceanspaces.com",
            "endpoint": "my-space.nyc3.cdn.digitaloceanspaces.com",
            "ttl": 3600,
            "created_at": "2012-10-02T15:00:01.05Z"
          },
          {
            "id": "892071a0-bb95-55bd-8021-3afd67a210bf",
            "origin": "my-space1.nyc3.digitaloceanspaces.com",
            "endpoint": "my-space1.nyc3.cdn.digitaloceanspaces.com",
            "ttl": 3600,
            "created_at": "2012-10-03T15:00:01.05Z"
          }
        ],
        "links":{"pages":{
  				"next":"http://example.com/v2/cdn/endpoints/?page=3",
  				"prev":"http://example.com/v2/cdn/endpoints/?page=1",
  				"last":"http://example.com/v2/cdn/endpoints/?page=3",
  				"first":"http://example.com/v2/cdn/endpoints/?page=1"}}
      }`,
		)
	})

	_, resp, err := client.CDNs.List(ctx, &ListOptions{Page: 2})
	if err != nil {
		t.Errorf("CDNs.List singular page returned error: %v", err)
	}

	checkCurrentPage(t, resp, 2)
}

func TestCDN_GetCDN(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints/12345", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(
			w,
			`{
        "endpoint": {
          "id": "12345",
          "origin": "my-space.nyc3.digitaloceanspaces.com",
          "endpoint": "my-space.nyc3.cdn.digitaloceanspaces.com",
          "ttl": 3600,
          "created_at": "2012-10-02T15:00:01.05Z"
        }
      }`,
		)
	})

	cdn, _, err := client.CDNs.Get(ctx, "12345")
	if err != nil {
		t.Errorf("CDNs.Get returned error: %v", err)
	}

	expected := &CDN{
		ID:        "12345",
		Origin:    "my-space.nyc3.digitaloceanspaces.com",
		Endpoint:  "my-space.nyc3.cdn.digitaloceanspaces.com",
		TTL:       3600,
		CreatedAt: time.Date(2012, 10, 02, 15, 00, 01, 50000000, time.UTC),
	}

	if !reflect.DeepEqual(cdn, expected) {
		t.Errorf("CDNs.Get returned %+v, expected %+v", cdn, expected)
	}
}

func TestCDN_CreateCDN(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		fmt.Fprint(
			w,
			`{
        "endpoint": {
          "id": "12345",
          "origin": "my-space.nyc3.digitaloceanspaces.com",
          "endpoint": "my-space.nyc3.cdn.digitaloceanspaces.com",
          "ttl": 3600,
          "created_at": "2012-10-02T15:00:01.05Z"
        }
      }`,
		)
	})

	req := &CDNCreateRequest{Origin: "my-space.nyc3.digitaloceanspaces.com", TTL: 3600}
	cdn, _, err := client.CDNs.Create(ctx, req)
	if err != nil {
		t.Errorf("CDNs.Create returned error: %v", err)
	}

	expected := &CDN{
		ID:        "12345",
		Origin:    "my-space.nyc3.digitaloceanspaces.com",
		Endpoint:  "my-space.nyc3.cdn.digitaloceanspaces.com",
		TTL:       3600,
		CreatedAt: time.Date(2012, 10, 02, 15, 00, 01, 50000000, time.UTC),
	}

	if !reflect.DeepEqual(cdn, expected) {
		t.Errorf("CDNs.Create returned %+v, expected %+v", cdn, expected)
	}
}

func TestCDN_DeleteCDN(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints/12345", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodDelete)
	})

	_, err := client.CDNs.Delete(ctx, "12345")
	if err != nil {
		t.Errorf("CDNs.Delete returned error: %v", err)
	}
}

func TestCDN_UpdateTTLCDN(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints/12345", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPut)
		fmt.Fprint(
			w,
			`{
        "endpoint": {
          "id": "12345",
          "origin": "my-space.nyc3.digitaloceanspaces.com",
          "endpoint": "my-space.nyc3.cdn.digitaloceanspaces.com",
          "ttl": 60,
          "created_at": "2012-10-02T15:00:01.05Z"
        }
      }`,
		)
	})

	req := &CDNUpdateRequest{TTL: 60}
	cdn, _, err := client.CDNs.UpdateTTL(ctx, "12345", req)
	if err != nil {
		t.Errorf("CDNs.UpdateTTL returned error: %v", err)
	}

	expected := &CDN{
		ID:        "12345",
		Origin:    "my-space.nyc3.digitaloceanspaces.com",
		Endpoint:  "my-space.nyc3.cdn.digitaloceanspaces.com",
		TTL:       60,
		CreatedAt: time.Date(2012, 10, 02, 15, 00, 01, 50000000, time.UTC),
	}

	if !reflect.DeepEqual(cdn, expected) {
		t.Errorf("CDNs.UpdateTTL returned %+v, expected %+v", cdn, expected)
	}
}

func TestCDN_FluchCacheCDN(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/cdn/endpoints/12345/cache", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodDelete)
	})

	req := &CDNFlushCacheRequest{Files: []string{"*"}}
	_, err := client.CDNs.FlushCache(ctx, "12345", req)
	if err != nil {
		t.Errorf("CDNs.FlushCache returned error: %v", err)
	}
}
