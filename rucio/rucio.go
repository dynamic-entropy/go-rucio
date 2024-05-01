package rucio

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
)

const (
	Version = "0.0.1"

	defaultUserAgent = "go-rucio/" + Version
	defaultTimeOut   = 600

	headerRucioAuthToken        = "X-Rucio-Auth-Token"
	headerRucioAuthTokenExpires = "X-Rucio-Auth-Token-Expires"
	headerRucioAccount          = "X-Rucio-Account"
)

type Client struct {
	httpClient *http.Client // HTTP client used to communicate with the API.

	// Base URL for API request
	rucioHost *url.URL
	authHost  *url.URL

	// User agent used when communicating with the Rucio API.
	userAccount string
	userAgent   string

	rucioAuthToken        string
	rucioAuthTokenExpires string

	logLevel slog.Level

	timeout int
	Account *AccountClient
	RSE     *RSEClient
}

type loggingRoundTripper struct {
	next http.RoundTripper
}

func (l loggingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	reqDump, _ := httputil.DumpRequestOut(r, true)
	fmt.Println(string(reqDump))

	resp, err := l.next.RoundTrip(r)
	if err != nil {
		return resp, err
	}

	respDump, _ := httputil.DumpResponse(resp, true)
	fmt.Println(string(respDump))
	return resp, err
}

func NewClient(rucioHost string, authHost string, userAccount string, clientCert string, clientKey string, caPath string, logLevel slog.Level) (*Client, error) {

	// Load client certificate
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		fmt.Println("Error loading client certificate: ", err)
		return nil, err
	}

	// Load CA certificates
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Println("Error reading system cert pool: ", err)
	}

	if caPath != "" {
		walkFunc := func(fpath string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				return nil
			}

			if filepath.Ext(de.Name()) == ".pem" || filepath.Ext(de.Name()) == ".0" {

				caCert, err := os.ReadFile(fpath)
				if err != nil {
					return err
				} else {
					caCertPool.AppendCertsFromPEM(caCert)
				}
			}
			return nil
		}
		if err = filepath.WalkDir(caPath, walkFunc); err != nil {
			fmt.Println("Error reading CA certificates", err)
			return nil, err
		}
	}

	authHostURL, err := url.Parse(authHost)
	if err != nil {
		fmt.Println("Error parsing rucio auth URL")
	}
	rucioHostURL, err := url.Parse(rucioHost)
	if err != nil {
		fmt.Println("Error parsing rucio URL")
	}

	var clientTransport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	if logLevel == slog.LevelDebug {
		clientTransport = &loggingRoundTripper{
			next: clientTransport,
		}
	}

	client := &Client{
		httpClient: &http.Client{
			Transport: clientTransport,
		},
		authHost:       authHostURL,
		rucioHost:      rucioHostURL,
		userAccount:    userAccount,
		timeout:        defaultTimeOut,
		userAgent:      defaultUserAgent,
		rucioAuthToken: "",
		logLevel:       logLevel,
	}

	return client, nil
}

func (client *Client) NewRequest(method string, path string, body interface{}) (*http.Request, error) {

	if client.rucioAuthToken == "" {
		client.getRucioAuthToken()
	}

	url, err := url.JoinPath(client.rucioHost.String(), path)
	if err != nil {
		fmt.Println("Error joining path to create url")
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println("Error creating rucio request for ")
	}

	req.Header.Set("User-Agent", client.userAgent)
	req.Header.Set(headerRucioAuthToken, client.rucioAuthToken)

	return req, nil
}

func (client *Client) Do(req *http.Request) (*http.Response, error) {
	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Println("Error creating request: ", err)
	}
	return resp, err
}

func (client *Client) getRucioAuthToken() {
	client.authHost.Path = "auth/x509_proxy"
	req, err := http.NewRequest(http.MethodGet, client.authHost.String(), nil)
	if err != nil {
		fmt.Println("Failed creating authentication request: ", err)
		return
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		fmt.Println("Failed to authenticate: ", err)
		return
	}
	client.rucioAuthToken = resp.Header.Get("X-Rucio-Auth-Token")
	client.rucioAuthTokenExpires = resp.Header.Get("X-Rucio-Auth-Token-Expires")
}
