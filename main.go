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

	"github.com/Merzlabs/pecuniatordotgo/xs2a"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	certFile  = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile   = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	caFile    = flag.String("CA", "someCertCAFile", "A PEM encoded CA's certificate file.")
	client    *http.Client
	processID string
	endpoints *xs2a.Endpoints
	tokens    *xs2a.Tokens
)

func main() {
	_ = godotenv.Load("secrets/sandbox.env")
	flag.Parse()
	setupClient()

	// AIS Consent
	consent := new(xs2a.ConsentResponse)
	err := startConsent(consent)
	if err != nil {
		log.Fatal(err)
	}

	// Get endpoints
	endpoints = new(xs2a.Endpoints)
	err = getEndpoints(endpoints)
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
	log.Printf("Please login here to proceed: %s", u.String())

	// Capture redirect and proceed after that
	http.HandleFunc("/redirect", authCodeHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func getToken(code string) error {
	tokens = new(xs2a.Tokens)

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

func authCodeHandler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Query().Get("state") == processID {
		code := req.URL.Query().Get("code")
		err := getToken(code)
		if err != nil {
			log.Fatalf("Failed to get token %s", err.Error())
		}
		log.Printf(tokens.AccessToken)
		fmt.Fprintf(w, "Authorization success. Token: %s\n", code)
	} else {
		fmt.Fprintf(w, "Authorization faile\n")
	}
}

func startConsent(consent *xs2a.ConsentResponse) error {
	accs := []xs2a.Account{xs2a.Account{IBAN: os.Getenv("PT_IBAN")}}
	access := &xs2a.ConsentAccess{
		Balances:     accs,
		Transactions: accs,
	}
	creq := &xs2a.ConsentRequest{
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
	headers := make(map[string]string)
	headers["Content-Type"] = contentType
	headers["X-Request-ID"] = uuid.New().String()
	headers["TPP-Redirect-URI"] = os.Getenv("PT_TPPREDIRECTURI")
	headers["TPP-Redirect-Preferred"] = "true"
	url := BuildURL("/consents")

	res, err := EncryptedPost(url, contentType, reader, headers)

	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(consent)
	return nil
}

func getEndpoints(target interface{}) error {
	res, err := EncryptedGet(os.Getenv("PT_WELLKNOWN"))
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
func EncryptedGet(url string) (*http.Response, error) {
	// Do GET something
	return client.Get(url)
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

	// Do GET something
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
