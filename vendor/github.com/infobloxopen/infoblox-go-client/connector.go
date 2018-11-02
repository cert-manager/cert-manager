package ibclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type HostConfig struct {
	Host     string
	Version  string
	Port     string
	Username string
	Password string
}

type TransportConfig struct {
	SslVerify           bool
	certPool            *x509.CertPool
	HttpRequestTimeout  time.Duration // in seconds
	HttpPoolConnections int
}

func NewTransportConfig(sslVerify string, httpRequestTimeout int, httpPoolConnections int) (cfg TransportConfig) {
	switch {
	case "false" == strings.ToLower(sslVerify):
		cfg.SslVerify = false
	case "true" == strings.ToLower(sslVerify):
		cfg.SslVerify = true
	default:
		caPool := x509.NewCertPool()
		cert, err := ioutil.ReadFile(sslVerify)
		if err != nil {
			log.Printf("Cannot load certificate file '%s'", sslVerify)
			return
		}
		if !caPool.AppendCertsFromPEM(cert) {
			err = fmt.Errorf("Cannot append certificate from file '%s'", sslVerify)
			return
		}
		cfg.certPool = caPool
		cfg.SslVerify = true
	}

	cfg.HttpPoolConnections = httpPoolConnections
	cfg.HttpRequestTimeout = time.Duration(httpRequestTimeout)
	return
}

type HttpRequestBuilder interface {
	Init(HostConfig)
	BuildUrl(r RequestType, objType string, ref string, returnFields []string, queryParams QueryParams) (urlStr string)
	BuildBody(r RequestType, obj IBObject) (jsonStr []byte)
	BuildRequest(r RequestType, obj IBObject, ref string, queryParams QueryParams) (req *http.Request, err error)
}

type HttpRequestor interface {
	Init(TransportConfig)
	SendRequest(*http.Request) ([]byte, error)
}

type WapiRequestBuilder struct {
	HostConfig HostConfig
}

type WapiHttpRequestor struct {
	client http.Client
}

type IBConnector interface {
	CreateObject(obj IBObject) (ref string, err error)
	GetObject(obj IBObject, ref string, res interface{}) error
	DeleteObject(ref string) (refRes string, err error)
	UpdateObject(obj IBObject, ref string) (refRes string, err error)
}

type Connector struct {
	HostConfig      HostConfig
	TransportConfig TransportConfig
	RequestBuilder  HttpRequestBuilder
	Requestor       HttpRequestor
}

type RequestType int

const (
	CREATE RequestType = iota
	GET
	DELETE
	UPDATE
)

func (r RequestType) toMethod() string {
	switch r {
	case CREATE:
		return "POST"
	case GET:
		return "GET"
	case DELETE:
		return "DELETE"
	case UPDATE:
		return "PUT"
	}

	return ""
}

func getHTTPResponseError(resp *http.Response) error {
	defer resp.Body.Close()
	content, _ := ioutil.ReadAll(resp.Body)
	msg := fmt.Sprintf("WAPI request error: %d('%s')\nContents:\n%s\n", resp.StatusCode, resp.Status, content)
	log.Printf(msg)
	return errors.New(msg)
}

func (whr *WapiHttpRequestor) Init(cfg TransportConfig) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.SslVerify,
			RootCAs: cfg.certPool},
		MaxIdleConnsPerHost: cfg.HttpPoolConnections,
	}

	// All users of cookiejar should import "golang.org/x/net/publicsuffix"
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}

	whr.client = http.Client{Jar: jar, Transport: tr, Timeout: cfg.HttpRequestTimeout * time.Second}
}

func (whr *WapiHttpRequestor) SendRequest(req *http.Request) (res []byte, err error) {
	var resp *http.Response
	resp, err = whr.client.Do(req)
	if err != nil {
		return
	} else if !(resp.StatusCode == http.StatusOK ||
		(resp.StatusCode == http.StatusCreated &&
			req.Method == RequestType(CREATE).toMethod())) {
		err := getHTTPResponseError(resp)
		return nil, err
	}
	defer resp.Body.Close()
	res, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Http Reponse ioutil.ReadAll() Error: '%s'", err)
		return
	}

	return
}

func (wrb *WapiRequestBuilder) Init(cfg HostConfig) {
	wrb.HostConfig = cfg
}

func (wrb *WapiRequestBuilder) BuildUrl(t RequestType, objType string, ref string, returnFields []string, queryParams QueryParams) (urlStr string) {
	path := []string{"wapi", "v" + wrb.HostConfig.Version}
	if len(ref) > 0 {
		path = append(path, ref)
	} else {
		path = append(path, objType)
	}

	qry := ""
	vals := url.Values{}
	if t == GET {
		if len(returnFields) > 0 {
			vals.Set("_return_fields", strings.Join(returnFields, ","))
		}
		// TODO need to get this from individual objects in future
		if queryParams.forceProxy {
			vals.Set("_proxy_search", "GM")
		}
		qry = vals.Encode()
	}

	u := url.URL{
		Scheme:   "https",
		Host:     wrb.HostConfig.Host + ":" + wrb.HostConfig.Port,
		Path:     strings.Join(path, "/"),
		RawQuery: qry,
	}

	return u.String()
}

func (wrb *WapiRequestBuilder) BuildBody(t RequestType, obj IBObject) []byte {
	var objJSON []byte
	var err error

	objJSON, err = json.Marshal(obj)
	if err != nil {
		log.Printf("Cannot marshal object '%s': %s", obj, err)
		return nil
	}

	eaSearch := obj.EaSearch()
	if t == GET && len(eaSearch) > 0 {
		eaSearchJSON, err := json.Marshal(eaSearch)
		if err != nil {
			log.Printf("Cannot marshal EA Search attributes. '%s'\n", err)
			return nil
		}
		objJSON = append(append(objJSON[:len(objJSON)-1], byte(',')), eaSearchJSON[1:]...)
	}

	return objJSON
}

func (wrb *WapiRequestBuilder) BuildRequest(t RequestType, obj IBObject, ref string, queryParams QueryParams) (req *http.Request, err error) {
	var (
		objType      string
		returnFields []string
	)
	if obj != nil {
		objType = obj.ObjectType()
		returnFields = obj.ReturnFields()
	}
	urlStr := wrb.BuildUrl(t, objType, ref, returnFields, queryParams)

	var bodyStr []byte
	if obj != nil {
		bodyStr = wrb.BuildBody(t, obj)
	}

	req, err = http.NewRequest(t.toMethod(), urlStr, bytes.NewBuffer(bodyStr))
	if err != nil {
		log.Printf("err1: '%s'", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(wrb.HostConfig.Username, wrb.HostConfig.Password)

	return
}

func (c *Connector) makeRequest(t RequestType, obj IBObject, ref string, queryParams QueryParams) (res []byte, err error) {
	var req *http.Request
	req, err = c.RequestBuilder.BuildRequest(t, obj, ref, queryParams)
	res, err = c.Requestor.SendRequest(req)
	if err != nil {
		/* Forcing the request to redirect to Grid Master by making forcedProxy=true */
		queryParams.forceProxy = true
		req, err = c.RequestBuilder.BuildRequest(t, obj, ref, queryParams)
		res, err = c.Requestor.SendRequest(req)
	}

	return
}

func (c *Connector) CreateObject(obj IBObject) (ref string, err error) {
	ref = ""
	queryParams := QueryParams{forceProxy: false}
	resp, err := c.makeRequest(CREATE, obj, "", queryParams)
	if err != nil || len(resp) == 0 {
		log.Printf("CreateObject request error: '%s'\n", err)
		return
	}

	err = json.Unmarshal(resp, &ref)
	if err != nil {
		log.Printf("Cannot unmarshall '%s', err: '%s'\n", string(resp), err)
		return
	}

	return
}

func (c *Connector) GetObject(obj IBObject, ref string, res interface{}) (err error) {
	queryParams := QueryParams{forceProxy: false}
	resp, err := c.makeRequest(GET, obj, ref, queryParams)
	//to check empty underlying value of interface
	var result []map[string]interface{}
	err = json.Unmarshal(resp, &result)
	if err != nil {
		log.Printf("Cannot unmarshall to check empty value '%s', err: '%s'\n", string(resp), err)
	}
	if resp == nil || len(result) == 0 {
		queryParams.forceProxy = true
		resp, err = c.makeRequest(GET, obj, ref, queryParams)
	}
	if err != nil {
		log.Printf("GetObject request error: '%s'\n", err)
	}
	if len(resp) == 0 {
		return
	}
	err = json.Unmarshal(resp, res)

	if err != nil {
		log.Printf("Cannot unmarshall '%s', err: '%s'\n", string(resp), err)
		return
	}
	return
}

func (c *Connector) DeleteObject(ref string) (refRes string, err error) {
	refRes = ""
	queryParams := QueryParams{forceProxy: false}
	resp, err := c.makeRequest(DELETE, nil, ref, queryParams)
	if err != nil {
		log.Printf("DeleteObject request error: '%s'\n", err)
		return
	}

	err = json.Unmarshal(resp, &refRes)
	if err != nil {
		log.Printf("Cannot unmarshall '%s', err: '%s'\n", string(resp), err)
		return
	}

	return
}

func (c *Connector) UpdateObject(obj IBObject, ref string) (refRes string, err error) {
	queryParams := QueryParams{forceProxy: false}
	refRes = ""
	resp, err := c.makeRequest(UPDATE, obj, ref, queryParams)
	if err != nil {
		log.Printf("Failed to update object %s: %s", obj.ObjectType(), err)
		return
	}

	err = json.Unmarshal(resp, &refRes)
	if err != nil {
		log.Printf("Cannot unmarshall update object response'%s', err: '%s'\n", string(resp), err)
		return
	}
	return
}

// Logout sends a request to invalidate the ibapauth cookie and should
// be used in a defer statement after the Connector has been successfully
// initialized.
func (c *Connector) Logout() (err error) {
	queryParams := QueryParams{forceProxy: false}
	_, err = c.makeRequest(CREATE, nil, "logout", queryParams)
	if err != nil {
		log.Printf("Logout request error: '%s'\n", err)
	}

	return
}

var ValidateConnector = validateConnector

func validateConnector(c *Connector) (err error) {
	// GET UserProfile request is used here to validate connector's basic auth and reachability.
	var response []UserProfile
	userprofile := NewUserProfile(UserProfile{})
	err = c.GetObject(userprofile, "", &response)
	if err != nil {
		log.Printf("Failed to connect to the Grid, err: %s \n", err)
	}
	return
}

func NewConnector(hostConfig HostConfig, transportConfig TransportConfig,
	requestBuilder HttpRequestBuilder, requestor HttpRequestor) (res *Connector, err error) {
	res = nil

	connector := &Connector{
		HostConfig:      hostConfig,
		TransportConfig: transportConfig,
	}

	//connector.RequestBuilder = WapiRequestBuilder{WaipHostConfig: connector.HostConfig}
	connector.RequestBuilder = requestBuilder
	connector.RequestBuilder.Init(connector.HostConfig)

	connector.Requestor = requestor
	connector.Requestor.Init(connector.TransportConfig)

	res = connector
	err = ValidateConnector(connector)
	return
}
