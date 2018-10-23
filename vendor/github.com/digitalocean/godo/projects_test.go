package godo

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestProjects_List(t *testing.T) {
	setup()
	defer teardown()

	projects := []Project{
		{
			ID:   "project-1",
			Name: "project-1",
		},
		{
			ID:   "project-2",
			Name: "project-2",
		},
	}

	mux.HandleFunc("/v2/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		resp, _ := json.Marshal(projects)
		fmt.Fprint(w, fmt.Sprintf(`{"projects":%s}`, string(resp)))
	})

	resp, _, err := client.Projects.List(ctx, nil)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}

	if !reflect.DeepEqual(resp, projects) {
		t.Errorf("Projects.List returned %+v, expected %+v", resp, projects)
	}
}

func TestProjects_ListWithMultiplePages(t *testing.T) {
	setup()
	defer teardown()

	mockResp := `
	{
		"projects": [
			{
				"uuid": "project-1",
				"name": "project-1"
			},
			{
				"uuid": "project-2",
				"name": "project-2"
			}
		],
		"links": {
			"pages": {
				"next": "http://example.com/v2/projects?page=2"
			}
		}
	}`

	mux.HandleFunc("/v2/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, mockResp)
	})

	_, resp, err := client.Projects.List(ctx, nil)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}

	checkCurrentPage(t, resp, 1)
}

func TestProjects_ListWithPageNumber(t *testing.T) {
	setup()
	defer teardown()

	mockResp := `
	{
		"projects": [
			{
				"uuid": "project-1",
				"name": "project-1"
			},
			{
				"uuid": "project-2",
				"name": "project-2"
			}
		],
		"links": {
			"pages": {
				"next": "http://example.com/v2/projects?page=3",
				"prev": "http://example.com/v2/projects?page=1",
				"last": "http://example.com/v2/projects?page=3",
				"first": "http://example.com/v2/projects?page=1"
			}
		}
	}`

	mux.HandleFunc("/v2/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, mockResp)
	})

	_, resp, err := client.Projects.List(ctx, &ListOptions{Page: 2})
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}

	checkCurrentPage(t, resp, 2)
}

func TestProjects_GetDefault(t *testing.T) {
	setup()
	defer teardown()

	project := &Project{
		ID:   "project-1",
		Name: "project-1",
	}

	mux.HandleFunc("/v2/projects/default", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		resp, _ := json.Marshal(project)
		fmt.Fprint(w, fmt.Sprintf(`{"project":%s}`, string(resp)))
	})

	resp, _, err := client.Projects.GetDefault(ctx)
	if err != nil {
		t.Errorf("Projects.GetDefault returned error: %v", err)
	}

	if !reflect.DeepEqual(resp, project) {
		t.Errorf("Projects.GetDefault returned %+v, expected %+v", resp, project)
	}
}

func TestProjects_GetWithUUID(t *testing.T) {
	setup()
	defer teardown()

	project := &Project{
		ID:   "project-1",
		Name: "project-1",
	}

	mux.HandleFunc("/v2/projects/project-1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		resp, _ := json.Marshal(project)
		fmt.Fprint(w, fmt.Sprintf(`{"project":%s}`, string(resp)))
	})

	resp, _, err := client.Projects.Get(ctx, "project-1")
	if err != nil {
		t.Errorf("Projects.Get returned error: %v", err)
	}

	if !reflect.DeepEqual(resp, project) {
		t.Errorf("Projects.Get returned %+v, expected %+v", resp, project)
	}
}

func TestProjects_Create(t *testing.T) {
	setup()
	defer teardown()

	createRequest := &CreateProjectRequest{
		Name:        "my project",
		Description: "for my stuff",
		Purpose:     "Just trying out DigitalOcean",
		Environment: "Production",
	}

	createResp := &Project{
		ID:          "project-id",
		Name:        createRequest.Name,
		Description: createRequest.Description,
		Purpose:     createRequest.Purpose,
		Environment: createRequest.Environment,
	}

	mux.HandleFunc("/v2/projects", func(w http.ResponseWriter, r *http.Request) {
		v := new(CreateProjectRequest)
		err := json.NewDecoder(r.Body).Decode(v)
		if err != nil {
			t.Fatalf("decode json: %v", err)
		}

		testMethod(t, r, http.MethodPost)
		if !reflect.DeepEqual(v, createRequest) {
			t.Errorf("Request body = %+v, expected %+v", v, createRequest)
		}

		resp, _ := json.Marshal(createResp)
		fmt.Fprintf(w, fmt.Sprintf(`{"project":%s}`, string(resp)))
	})

	project, _, err := client.Projects.Create(ctx, createRequest)
	if err != nil {
		t.Errorf("Projects.Create returned error: %v", err)
	}

	if !reflect.DeepEqual(project, createResp) {
		t.Errorf("Projects.Create returned %+v, expected %+v", project, createResp)
	}
}

func TestProjects_UpdateWithOneAttribute(t *testing.T) {
	setup()
	defer teardown()

	updateRequest := &UpdateProjectRequest{
		Name: "my-great-project",
	}
	updateResp := &Project{
		ID:          "project-id",
		Name:        updateRequest.Name.(string),
		Description: "some-other-description",
		Purpose:     "some-other-purpose",
		Environment: "some-other-env",
		IsDefault:   false,
	}

	mux.HandleFunc("/v2/projects/project-1", func(w http.ResponseWriter, r *http.Request) {
		reqBytes, respErr := ioutil.ReadAll(r.Body)
		if respErr != nil {
			t.Error("projects mock didn't work")
		}

		req := strings.TrimSuffix(string(reqBytes), "\n")
		expectedReq := `{"name":"my-great-project","description":null,"purpose":null,"environment":null,"is_default":null}`
		if req != expectedReq {
			t.Errorf("projects req didn't match up:\n expected %+v\n got %+v\n", expectedReq, req)
		}

		resp, _ := json.Marshal(updateResp)
		fmt.Fprintf(w, fmt.Sprintf(`{"project":%s}`, string(resp)))
	})

	project, _, err := client.Projects.Update(ctx, "project-1", updateRequest)
	if err != nil {
		t.Errorf("Projects.Update returned error: %v", err)
	}
	if !reflect.DeepEqual(project, updateResp) {
		t.Errorf("Projects.Update returned %+v, expected %+v", project, updateResp)
	}
}

func TestProjects_UpdateWithAllAttributes(t *testing.T) {
	setup()
	defer teardown()

	updateRequest := &UpdateProjectRequest{
		Name:        "my-great-project",
		Description: "some-description",
		Purpose:     "some-purpose",
		Environment: "some-env",
		IsDefault:   true,
	}
	updateResp := &Project{
		ID:          "project-id",
		Name:        updateRequest.Name.(string),
		Description: updateRequest.Description.(string),
		Purpose:     updateRequest.Purpose.(string),
		Environment: updateRequest.Environment.(string),
		IsDefault:   updateRequest.IsDefault.(bool),
	}

	mux.HandleFunc("/v2/projects/project-1", func(w http.ResponseWriter, r *http.Request) {
		reqBytes, respErr := ioutil.ReadAll(r.Body)
		if respErr != nil {
			t.Error("projects mock didn't work")
		}

		req := strings.TrimSuffix(string(reqBytes), "\n")
		expectedReq := `{"name":"my-great-project","description":"some-description","purpose":"some-purpose","environment":"some-env","is_default":true}`
		if req != expectedReq {
			t.Errorf("projects req didn't match up:\n expected %+v\n got %+v\n", expectedReq, req)
		}

		resp, _ := json.Marshal(updateResp)
		fmt.Fprintf(w, fmt.Sprintf(`{"project":%s}`, string(resp)))
	})

	project, _, err := client.Projects.Update(ctx, "project-1", updateRequest)
	if err != nil {
		t.Errorf("Projects.Update returned error: %v", err)
	}
	if !reflect.DeepEqual(project, updateResp) {
		t.Errorf("Projects.Update returned %+v, expected %+v", project, updateResp)
	}
}

func TestProjects_Destroy(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v2/projects/project-1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodDelete)
	})

	_, err := client.Projects.Delete(ctx, "project-1")
	if err != nil {
		t.Errorf("Projects.Delete returned error: %v", err)
	}
}

func TestProjects_ListResources(t *testing.T) {
	setup()
	defer teardown()

	resources := []ProjectResource{
		{
			URN:        "do:droplet:1",
			AssignedAt: "2018-09-27 00:00:00",
			Links: &ProjectResourceLinks{
				Self: "http://example.com/v2/droplets/1",
			},
		},
		{
			URN:        "do:floatingip:1.2.3.4",
			AssignedAt: "2018-09-27 00:00:00",
			Links: &ProjectResourceLinks{
				Self: "http://example.com/v2/floating_ips/1.2.3.4",
			},
		},
	}

	mux.HandleFunc("/v2/projects/project-1/resources", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		resp, _ := json.Marshal(resources)
		fmt.Fprint(w, fmt.Sprintf(`{"resources":%s}`, string(resp)))
	})

	resp, _, err := client.Projects.ListResources(ctx, "project-1", nil)
	if err != nil {
		t.Errorf("Projects.List returned error: %v", err)
	}

	if !reflect.DeepEqual(resp, resources) {
		t.Errorf("Projects.ListResources returned %+v, expected %+v", resp, resources)
	}
}

func TestProjects_ListResourcesWithMultiplePages(t *testing.T) {
	setup()
	defer teardown()

	mockResp := `
	{
		"resources": [
			{
				"urn": "do:droplet:1",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/droplets/1"
				}
			},
			{
				"urn": "do:floatingip:1.2.3.4",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/floating_ips/1.2.3.4"
				}
			}
		],
		"links": {
			"pages": {
				"next": "http://example.com/v2/projects/project-1/resources?page=2"
			}
		}
	}`

	mux.HandleFunc("/v2/projects/project-1/resources", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, mockResp)
	})

	_, resp, err := client.Projects.ListResources(ctx, "project-1", nil)
	if err != nil {
		t.Errorf("Projects.ListResources returned error: %v", err)
	}

	checkCurrentPage(t, resp, 1)
}

func TestProjects_ListResourcesWithPageNumber(t *testing.T) {
	setup()
	defer teardown()

	mockResp := `
	{
		"resources": [
			{
				"urn": "do:droplet:1",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/droplets/1"
				}
			},
			{
				"urn": "do:floatingip:1.2.3.4",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/floating_ips/1.2.3.4"
				}
			}
		],
		"links": {
			"pages": {
				"next": "http://example.com/v2/projects/project-1/resources?page=3",
				"prev": "http://example.com/v2/projects/project-1/resources?page=1",
				"last": "http://example.com/v2/projects/project-1/resources?page=3",
				"first": "http://example.com/v2/projects/project-1/resources?page=1"
			}
		}
	}`

	mux.HandleFunc("/v2/projects/project-1/resources", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, mockResp)
	})

	_, resp, err := client.Projects.ListResources(ctx, "project-1", &ListOptions{Page: 2})
	if err != nil {
		t.Errorf("Projects.ListResources returned error: %v", err)
	}

	checkCurrentPage(t, resp, 2)
}

func TestProjects_AssignFleetResourcesWithTypes(t *testing.T) {
	setup()
	defer teardown()

	assignableResources := []interface{}{
		&Droplet{ID: 1234},
		&FloatingIP{IP: "1.2.3.4"},
	}

	mockResp := `
	{
		"resources": [
			{
				"urn": "do:droplet:1234",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/droplets/1"
				}
			},
			{
				"urn": "do:floatingip:1.2.3.4",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/floating_ips/1.2.3.4"
				}
			}
		]
	}`

	mux.HandleFunc("/v2/projects/project-1/resources", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		reqBytes, respErr := ioutil.ReadAll(r.Body)
		if respErr != nil {
			t.Error("projects mock didn't work")
		}

		req := strings.TrimSuffix(string(reqBytes), "\n")
		expectedReq := `{"resources":["do:droplet:1234","do:floatingip:1.2.3.4"]}`
		if req != expectedReq {
			t.Errorf("projects assign req didn't match up:\n expected %+v\n got %+v\n", expectedReq, req)
		}

		fmt.Fprint(w, mockResp)
	})

	_, _, err := client.Projects.AssignResources(ctx, "project-1", assignableResources...)
	if err != nil {
		t.Errorf("Projects.AssignResources returned error: %v", err)
	}
}

func TestProjects_AssignFleetResourcesWithStrings(t *testing.T) {
	setup()
	defer teardown()

	assignableResources := []interface{}{
		"do:droplet:1234",
		"do:floatingip:1.2.3.4",
	}

	mockResp := `
	{
		"resources": [
			{
				"urn": "do:droplet:1234",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/droplets/1"
				}
			},
			{
				"urn": "do:floatingip:1.2.3.4",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/floating_ips/1.2.3.4"
				}
			}
		]
	}`

	mux.HandleFunc("/v2/projects/project-1/resources", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		reqBytes, respErr := ioutil.ReadAll(r.Body)
		if respErr != nil {
			t.Error("projects mock didn't work")
		}

		req := strings.TrimSuffix(string(reqBytes), "\n")
		expectedReq := `{"resources":["do:droplet:1234","do:floatingip:1.2.3.4"]}`
		if req != expectedReq {
			t.Errorf("projects assign req didn't match up:\n expected %+v\n got %+v\n", expectedReq, req)
		}

		fmt.Fprint(w, mockResp)
	})

	_, _, err := client.Projects.AssignResources(ctx, "project-1", assignableResources...)
	if err != nil {
		t.Errorf("Projects.AssignResources returned error: %v", err)
	}
}

func TestProjects_AssignFleetResourcesWithStringsAndTypes(t *testing.T) {
	setup()
	defer teardown()

	assignableResources := []interface{}{
		"do:droplet:1234",
		&FloatingIP{IP: "1.2.3.4"},
	}

	mockResp := `
	{
		"resources": [
			{
				"urn": "do:droplet:1234",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/droplets/1"
				}
			},
			{
				"urn": "do:floatingip:1.2.3.4",
				"assigned_at": "2018-09-27 00:00:00",
				"links": {
					"self": "http://example.com/v2/floating_ips/1.2.3.4"
				}
			}
		]
	}`

	mux.HandleFunc("/v2/projects/project-1/resources", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		reqBytes, respErr := ioutil.ReadAll(r.Body)
		if respErr != nil {
			t.Error("projects mock didn't work")
		}

		req := strings.TrimSuffix(string(reqBytes), "\n")
		expectedReq := `{"resources":["do:droplet:1234","do:floatingip:1.2.3.4"]}`
		if req != expectedReq {
			t.Errorf("projects assign req didn't match up:\n expected %+v\n got %+v\n", expectedReq, req)
		}

		fmt.Fprint(w, mockResp)
	})

	_, _, err := client.Projects.AssignResources(ctx, "project-1", assignableResources...)
	if err != nil {
		t.Errorf("Projects.AssignResources returned error: %v", err)
	}
}

func TestProjects_AssignFleetResourcesWithTypeWithoutURNReturnsError(t *testing.T) {
	setup()
	defer teardown()

	type fakeType struct{}

	assignableResources := []interface{}{
		fakeType{},
	}

	_, _, err := client.Projects.AssignResources(ctx, "project-1", assignableResources...)
	if err == nil {
		t.Errorf("expected Projects.AssignResources to error, but it did not")
	}

	if err.Error() != "godo.fakeType must either be a string or have a valid URN method" {
		t.Errorf("Projects.AssignResources returned the wrong error: %v", err)
	}
}
