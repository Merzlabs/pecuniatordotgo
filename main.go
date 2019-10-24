package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Merzlabs/pecuniatordotgo/oauth"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	certFile  = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile   = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	caFile    = flag.String("CA", "someCertCAFile", "A PEM encoded CA's certificate file.")
	client    *http.Client
	processID string
	endpoints *oauth.Endpoints
	tokens    *oauth.Tokens
	consent   *oauth.ConsentResponse
	requestID string
)

func main() {
	_ = godotenv.Load("secrets/sandbox.env")
	flag.Parse()
	setupClient()
	// Get endpoints
	endpoints = new(oauth.Endpoints)
	err := getEndpoints(endpoints)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Start server on localhost:8080")
	http.HandleFunc("/index", indexHandler)
	http.HandleFunc("/redirect", authHandler)
	http.HandleFunc("/accounts", accountHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func readAccountList() (string, error) {
	headers := make(map[string]string)
	headers["X-Request-ID"] = uuid.New().String()
	headers["Consent-ID"] = consent.ID
	headers["Authorization"] = tokens.TokenType + " " + tokens.AccessToken

	res, err := EncryptedGet(BuildURL("/accounts"), headers)

	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}

func getToken(code string) error {
	tokens = new(oauth.Tokens)

	// Exchange code for token
	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", "pecuniatordotgo")
	form.Add("code_verifier", "TODO") // TODO see PKCE (Proof  Key  for Code Exchange RFC 7636)
	form.Add("grant_type", "authorization_code")

	contentType := "application/x-www-form-urlencoded"
	headers := make(map[string]string)
	headers["Content-Type"] = contentType
	res, err := EncryptedPost(endpoints.Token, contentType, strings.NewReader(form.Encode()), headers)
	if err != nil {
		return err
	}

	return json.NewDecoder(res.Body).Decode(tokens)
}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	// AIS Consent
	consent = new(oauth.ConsentResponse)
	err := startConsent(consent)
	if err != nil {
		log.Fatal(err)
	}

	// Print redirect link
	processID = uuid.New().String()
	u, err := url.Parse(endpoints.Authorization)
	if err != nil {
		log.Fatal(err)
	}
	params := url.Values{}
	params.Add("responseType", "code")
	params.Add("clientId", "pecuniatordotgo")
	params.Add("scope", "AIS: "+consent.ID)
	params.Add("state", processID)
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", "vXVXiMA4CQ_Buik94dCNpfIfveWdNxMEwVtxGDz7xWg")

	u.RawQuery = params.Encode()

	fmt.Fprintf(w, "<a href=\"%s\">Please login at your bank to proceed</a>", u.String())
}

func authHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Query().Get("state") == processID {
		code := req.URL.Query().Get("code")
		err := getToken(code)
		if err != nil {
			log.Fatalf("Failed to get token %s", err.Error())
		}

		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Authorization success. <a href=\"/accounts\">Get accounts</a>\n")
	} else {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Authorization failed\n")
	}
}

func accountHandler(w http.ResponseWriter, req *http.Request) {
	data, err := readAccountList()
	if err != nil {
		fmt.Fprintf(w, "<a href=\"/index\">Start</a><br> Data error: <br> %s\n", err.Error())
		return
	}
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprintf(w, data)
}

func startConsent(consent *oauth.ConsentResponse) error {
	accs := []oauth.Account{oauth.Account{IBAN: os.Getenv("PT_IBAN")}}
	access := &oauth.ConsentAccess{
		Balances:     accs,
		Transactions: accs,
	}
	creq := &oauth.ConsentRequest{
		Access:                   *access,
		RecurringIndicator:       true,
		ValidUntil:               "2019-10-30", //TODO generate usefull value
		FrequencyPerDay:          4,
		CombinedServiceIndicator: false,
	}
	data, err := json.Marshal(creq)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(data)

	contentType := "application/json"
	requestID = uuid.New().String()
	headers := make(map[string]string)
	headers["Content-Type"] = contentType
	headers["X-Request-ID"] = requestID
	headers["TPP-Redirect-URI"] = os.Getenv("PT_TPPREDIRECTURI")
	headers["TPP-Redirect-Preferred"] = "true"
	url := BuildURL("/consents")

	res, err := EncryptedPost(url, contentType, reader, headers)

	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(consent)
}

func getEndpoints(target interface{}) error {
	res, err := EncryptedGet(os.Getenv("PT_WELLKNOWN"), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

// Based on https://gist.github.com/michaljemala/d6f4e01c4834bf47a9c4
func setupClient() {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool, _ := x509.SystemCertPool()
	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client = &http.Client{Transport: transport}
}

// EncryptedGet uses the certificates for connecting to the API
func EncryptedGet(url string, header map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	return client.Do(req)
}

// EncryptedPost uses the certificates for connecting to the API
func EncryptedPost(url string, contenttype string, body io.Reader, header map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)

	if err != nil {
		return nil, err
	}

	for key, value := range header {
		req.Header.Set(key, value)
	}

	return client.Do(req)
}

// BuildURL creates the complete url form params and environment
func BuildURL(suffix string) string {
	url := url.URL{
		Scheme: "https",
		Host:   os.Getenv("PT_HOST") + ":" + os.Getenv("PT_PORT"),
		Path:   os.Getenv("PT_PATH") + "/" + os.Getenv("PT_VERS") + suffix,
	}
	return url.String()
}
